import json
import os
import time
import urllib.error
import urllib.request
from mitmproxy import http

AKTO_AUTHORIZATION = os.environ.get("AKTO_AUTHORIZATION", "")
AKTO_ACCOUNT_ID = os.environ.get("AKTO_ACCOUNT_ID", "")
AKTO_VXLAN_ID = os.environ.get("AKTO_VXLAN_ID", "")

AKTO_GUARDRAILS_HOST = f"https://{AKTO_ACCOUNT_ID}-guardrails.akto.io"
VALIDATE_REQUEST_URL = f"{AKTO_GUARDRAILS_HOST}/api/validate/request"
VALIDATE_RESPONSE_URL = f"{AKTO_GUARDRAILS_HOST}/api/validate/response"

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


def build_base_payload(flow):
    return {
        "path": flow.request.path,
        "method": flow.request.method,
        "requestHeaders": json.dumps(dict(flow.request.headers)),
        "requestPayload": flow.request.get_text(strict=False),
        "authorization": AKTO_AUTHORIZATION,
        "ip": flow.client_conn.peername[0] if flow.client_conn else "127.0.0.1",
        "destIp": flow.server_conn.address[0] if flow.server_conn else "127.0.0.1",
        "time": str(int(time.time() * 1000)),
        "statusCode": "200",
        "status": "200",
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


def is_blocked(resp):
    if not resp:
        return False

    return resp.get("Allowed") is False


def return_akto_error(flow, validation):
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
            "X-Akto-Guardrail-Reason": validation.get(
                "Reason",
                "Request blocked by Akto"
            )
        }
    )


def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host

    if "bedrock-runtime" not in host:
        return

    print("\n================ REQUEST ================")
    print(flow.request.method)
    print(flow.request.pretty_url)

    payload = build_base_payload(flow)

    validation = post_json(
        VALIDATE_REQUEST_URL,
        payload
    )

    print("\n================ REQUEST VALIDATION ================")
    print(json.dumps(validation, indent=2))

    if is_blocked(validation):
        print(">>> REQUEST BLOCKED BY AKTO")
        return_akto_error(flow, validation)
        return

    print(">>> REQUEST ALLOWED")

    pending[flow.id] = payload


def response(flow: http.HTTPFlow):
    if flow.id not in pending:
        return

    payload = pending.pop(flow.id)

    response_body = flow.response.get_text(strict=False)

    payload["responseHeaders"] = json.dumps(
        dict(flow.response.headers)
    )
    payload["responsePayload"] = response_body
    payload["statusCode"] = str(flow.response.status_code)
    payload["status"] = str(flow.response.status_code)

    print("\n================ RESPONSE ================")
    print(response_body[:2000])

    response_validation = post_json(
        VALIDATE_RESPONSE_URL,
        payload
    )

    print("\n================ RESPONSE VALIDATION ================")
    print(json.dumps(response_validation, indent=2))

    if is_blocked(response_validation):
        print(">>> RESPONSE BLOCKED BY AKTO")
        return_akto_error(flow, response_validation)
        return

    print(">>> RESPONSE ALLOWED")