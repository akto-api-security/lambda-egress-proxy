import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse
from mitmproxy import http

AKTO_AUTHORIZATION = os.environ.get("AKTO_AUTHORIZATION", "")
AKTO_ACCOUNT_ID = os.environ.get("AKTO_ACCOUNT_ID", "")
AKTO_VXLAN_ID = os.environ.get("AKTO_VXLAN_ID", "")

REQUIRED_VALIDATE_QUERY_PARAMS = {
    "guardrails": "true",
    "ingest_data": "true",
    "response_guardrails": "true",
}

AKTO_HEALTH_PATH = os.environ.get("AKTO_HEALTH_PATH", "/akto-health")

# When Akto returns no usable verdict (timeout, unreachable backend, malformed
# body), "false" lets traffic through unvalidated and "true" blocks it.
AKTO_FAIL_CLOSED = os.environ.get("AKTO_FAIL_CLOSED", "false").lower() == "true"


def with_required_query_params(url, required):
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query))
    for key, value in required.items():
        query.setdefault(key, value)
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


AKTO_VALIDATE_URL = with_required_query_params(
    os.environ.get("AKTO_VALIDATE_URL", ""), REQUIRED_VALIDATE_QUERY_PARAMS
)

def check_https_proxy_reachable():
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy_url:
        print("[PROXY CHECK] HTTPS_PROXY not set, skipping reachability check")
        return

    p = urlparse(proxy_url)
    try:
        socket.create_connection((p.hostname, p.port), timeout=5).close()
        print(f"[PROXY CHECK] PROXY REACHABLE {p.hostname}:{p.port}")
    except Exception as e:
        print(f"[PROXY CHECK] PROXY UNREACHABLE {p.hostname}:{p.port} {e!r}")


check_https_proxy_reachable()

pending = {}


def post_json(url, payload):
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json"
            }
        )

        # Do not send the proxy's own Akto calls back through mitmproxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=15) as response:
            body = response.read().decode("utf-8", errors="replace")

            print(f"\n[AKTO] {url}")
            print(f"[AKTO STATUS] {response.status}")
            print(f"[AKTO BODY] {body}")

            try:
                return json.loads(body)
            except Exception:
                return {
                    "statusCode": response.status,
                    "body": body
                }

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")

        print(f"\n[AKTO HTTP ERROR] {url}")
        print(f"[AKTO STATUS] {e.code}")
        print(f"[AKTO BODY] {body}")

        try:
            return json.loads(body)
        except Exception:
            return {
                "statusCode": e.code,
                "body": body
            }

    except Exception as e:
        print(f"[AKTO ERROR] {url}: {e}")
        return None


def readable_path(request):
    """Percent-decode the path for Akto only - boto3 encodes the colon in
    model ids (amazon.nova-lite-v1%3A0), which makes endpoints unreadable and
    splits them in the dashboard. The query string is left exactly as sent,
    since decoding it could change parameter boundaries. The outbound request
    is never touched: Bedrock needs the original encoding, and it is covered
    by the SigV4 signature.
    """
    parts = urllib.parse.urlsplit(request.path)
    return urllib.parse.urlunsplit(
        ("", "", urllib.parse.unquote(parts.path), parts.query, parts.fragment)
    )


def build_base_payload(flow):
    return {
        "path": readable_path(flow.request),
        "method": flow.request.method,
        "requestHeaders": json.dumps(dict(flow.request.headers)),
        "requestPayload": flow.request.get_text(strict=False),
        "responseHeaders": "{}",
        "responsePayload": "{}",
        "authorization": AKTO_AUTHORIZATION,
        "ip": flow.client_conn.peername[0] if flow.client_conn else "127.0.0.1",
        "destIp": flow.server_conn.address[0] if flow.server_conn else "127.0.0.1",
        "time": str(int(time.time() * 1000)),
        "statusCode": "200",
        "status": "200",
        "type": None,
        "direction": None,
        "process_id": None,
        "socket_id": None,
        "daemonset_id": None,
        "enabled_graph": None,
        "akto_account_id": AKTO_ACCOUNT_ID,
        "akto_vxlan_id": AKTO_VXLAN_ID,
        "is_pending": "false",
        "source": "MIRRORING",
        "tag": json.dumps({
            "gen-ai": "Gen AI",
            "ai-agent": "bedrock",
            "source": "AGENTIC"
        }),
        "metadata": json.dumps({
            "gen-ai": "Gen AI",
            "ai-agent": "bedrock",
            "source": "AGENTIC"
        }),
        "contextSource": "AGENTIC"
    }


def _guardrails_result(resp):
    """Akto nests the verdict under data.guardrailsResult - never top level."""
    return ((resp or {}).get("data") or {}).get("guardrailsResult") or {}


def is_blocked(resp, phase=None):
    result = _guardrails_result(resp)
    if not result:
        return AKTO_FAIL_CLOSED

    # Per-phase verdicts live in requestResult / responseResult; the
    # guardrailsResult-level Allowed is the combined fallback.
    phase_result = result.get(phase) if phase else None
    if isinstance(phase_result, dict) and "Allowed" in phase_result:
        return phase_result.get("Allowed") is False

    return result.get("Allowed") is False


def block_reason(resp, phase=None, default="Request blocked by Akto"):
    result = _guardrails_result(resp)
    phase_result = result.get(phase) if phase else None
    if isinstance(phase_result, dict) and phase_result.get("Reason"):
        return str(phase_result["Reason"])
    return str(result.get("Reason") or default)


def modified_payload(resp, phase=None):
    """Replacement body when guardrails redacted/rewrote the content."""
    result = _guardrails_result(resp)
    phase_result = result.get(phase) if phase else None
    for candidate in (phase_result, result):
        if not isinstance(candidate, dict):
            continue
        if candidate.get("Modified") and candidate.get("ModifiedPayload"):
            return candidate["ModifiedPayload"]
    return None


def return_akto_error(flow, validation, phase=None):
    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("         BLOCKED BY AKTO")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(json.dumps(validation, indent=2))
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    body = json.dumps(validation)
    flow.response = http.Response.make(
        403,
        body,
        {
            "Content-Type": "application/json",
            "X-Akto-Guardrail": "blocked",
            "X-Akto-Guardrail-Reason": block_reason(validation, phase)
        }
    )


def request(flow: http.HTTPFlow):
    if flow.request.path.startswith(AKTO_HEALTH_PATH):
        print(f"\n[HEALTH CHECK] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(
            200,
            json.dumps({"status": "ok"}),
            {"Content-Type": "application/json"}
        )
        return
    host = flow.request.pretty_host

    if "bedrock-runtime" not in host:
        return

    print("\n================ REQUEST ================")
    print(flow.request.method)
    print(flow.request.pretty_url)

    payload = build_base_payload(flow)

    validation = post_json(
        AKTO_VALIDATE_URL,
        payload
    )

    print("\n================ REQUEST VALIDATION ================")
    print(json.dumps(validation, indent=2))

    if is_blocked(validation, "requestResult"):
        print(">>> REQUEST BLOCKED BY AKTO")
        return_akto_error(flow, validation, "requestResult")
        return

    # Request-side ModifiedPayload is deliberately NOT applied: SigV4 signs the
    # body hash, so rewriting it invalidates the signature and AWS rejects the
    # call with InvalidSignatureException. Re-signing would need the caller's
    # credentials. Blocking is the enforceable option on the request leg;
    # rewriting only works on responses, which carry no signature.
    print(">>> REQUEST ALLOWED")

    pending[flow.id] = payload


def response(flow: http.HTTPFlow):
    if flow.id not in pending:
        return

    payload = pending.pop(flow.id)

    response_body = flow.response.get_text(strict=False)

    payload["requestHeaders"] = "{}"
    payload["requestPayload"] = "{}"
    payload["responseHeaders"] = json.dumps(
        dict(flow.response.headers)
    )
    payload["responsePayload"] = response_body
    payload["statusCode"] = str(flow.response.status_code)
    payload["status"] = str(flow.response.status_code)

    print("\n================ RESPONSE ================")
    print(response_body[:2000])

    response_validation = post_json(
        AKTO_VALIDATE_URL,
        payload
    )

    print("\n================ RESPONSE VALIDATION ================")
    print(json.dumps(response_validation, indent=2))

    if is_blocked(response_validation, "responseResult"):
        print(">>> RESPONSE BLOCKED BY AKTO")
        return_akto_error(flow, response_validation, "responseResult")
        return

    modified = modified_payload(response_validation, "responseResult")
    if modified is not None:
        print(">>> RESPONSE MODIFIED BY AKTO")
        flow.response.set_text(modified)

    print(">>> RESPONSE ALLOWED")