import base64
import json
import os
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse
from mitmproxy import http

AKTO_AUTHORIZATION = os.environ.get("AKTO_AUTHORIZATION", "")

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
        "akto_account_id": "",
        "akto_vxlan_id": "",
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


def decode_event_stream(raw):
    """Yield (event type, JSON body) per AWS event-stream frame. Bedrock only
    sends string headers (type 7), so other header types are not handled."""
    offset = 0
    while offset + 12 <= len(raw):
        total_len, headers_len = struct.unpack_from(">II", raw, offset)
        if total_len < 16 or offset + total_len > len(raw):
            return
        headers, i, end = {}, offset + 12, offset + 12 + headers_len
        while i < end and raw[i + 1 + raw[i]] == 7:
            name = raw[i + 1:i + 1 + raw[i]].decode()
            i += 2 + raw[i]
            (value_len,) = struct.unpack_from(">H", raw, i)
            headers[name] = raw[i + 2:i + 2 + value_len].decode()
            i += 2 + value_len
        if headers.get(":message-type") == "event":
            yield headers.get(":event-type"), json.loads(raw[end:offset + total_len - 4])
        offset += total_len


# Tool calls and results from every model format are normalized to
# {id, name, input} and {id, content, is_error}. Formats covered: Converse and
# Nova (toolUse/toolResult), Anthropic (tool_use/tool_result), OpenAI-style
# chat - gpt-oss, Mistral, AI21, Qwen, DeepSeek (tool_calls / role "tool"),
# and Cohere (tool_calls / tool_results). Llama emits tool calls as plain text,
# so its traffic is validated but tool calls are not extracted.

def _json_or_raw(value):
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value) if value else {}
    except ValueError:
        return value


def tool_calls_in(message):
    """Tool calls in an assistant message or non-streaming response body."""
    calls = []
    content = message.get("content")
    for b in content if isinstance(content, list) else []:
        if "toolUse" in b:
            t = b["toolUse"]
            calls.append({"id": t.get("toolUseId"), "name": t.get("name"), "input": t.get("input")})
        elif b.get("type") == "tool_use":
            calls.append({"id": b.get("id"), "name": b.get("name"), "input": b.get("input")})
    for t in message.get("tool_calls") or []:
        if "function" in t:
            fn = t["function"]
            calls.append({"id": t.get("id"), "name": fn.get("name"), "input": _json_or_raw(fn.get("arguments"))})
        else:  # Cohere calls carry no id
            calls.append({"id": t.get("name"), "name": t.get("name"), "input": t.get("parameters")})
    return calls


def response_message(body):
    if "output" in body:
        return body["output"].get("message") or {}
    if body.get("choices"):
        return body["choices"][0].get("message") or {}
    return body


def parse_stream(raw):
    """(text, tool calls, decoded events) from a ConverseStream or
    InvokeModelWithResponseStream body."""
    text, calls, events = [], {}, []
    for event, body in decode_event_stream(raw):
        if event == "chunk":
            body = json.loads(base64.b64decode(body["bytes"]))
            # Nova's InvokeModel stream wraps Converse events: {"contentBlockDelta": {...}}
            wrapped = next((k for k in ("contentBlockStart", "contentBlockDelta") if k in body), None)
            event, body = (wrapped, body[wrapped]) if wrapped else (body.get("type") or body.get("event_type"), body)
        events.append(body)
        index = body.get("contentBlockIndex", body.get("index"))

        if event == "contentBlockStart" and "toolUse" in body.get("start", {}):
            t = body["start"]["toolUse"]
            calls[index] = {"id": t.get("toolUseId"), "name": t.get("name"), "input": ""}
        elif event == "content_block_start" and body["content_block"].get("type") == "tool_use":
            b = body["content_block"]
            calls[index] = {"id": b.get("id"), "name": b.get("name"), "input": ""}
        elif event in ("contentBlockDelta", "content_block_delta"):
            delta = body.get("delta", {})
            text.append(delta.get("text", ""))
            if index in calls:
                calls[index]["input"] += (delta.get("toolUse") or {}).get("input", "") or delta.get("partial_json", "")
        elif event == "tool-calls-generation":
            for t in body.get("tool_calls") or []:
                calls[len(calls)] = {"id": t.get("name"), "name": t.get("name"), "input": t.get("parameters")}
        elif event == "text-generation":
            text.append(body.get("text", ""))
        elif body.get("choices"):
            choice = body["choices"][0]
            message = choice.get("delta") or choice.get("message") or {}
            text.append(message.get("content") or choice.get("text") or "")
            for i, t in enumerate(message.get("tool_calls") or []):
                call = calls.setdefault(t.get("index", i), {"id": None, "name": None, "input": ""})
                fn = t.get("function") or {}
                call["id"] = t.get("id") or call["id"]
                call["name"] = fn.get("name") or call["name"]
                call["input"] += fn.get("arguments") or ""
        else:  # Llama, Titan, legacy Claude text completions
            text.append(body.get("generation") or body.get("outputText") or body.get("completion") or "")

    for call in calls.values():
        call["input"] = _json_or_raw(call["input"])
    return "".join(text), list(calls.values()), events


def tool_results_in_request(flow):
    """(tool call, result) pairs for the results new in this request. The whole
    conversation is resent on every call, so older ones were already reported."""
    try:
        body = json.loads(flow.request.get_text(strict=False))
        messages = body.get("messages") or []
    except (ValueError, AttributeError):
        return []

    if body.get("tool_results"):  # Cohere sends only the current turn's results
        return [(
            {"id": r["call"].get("name"), "name": r["call"].get("name"), "input": r["call"].get("parameters")},
            {"id": r["call"].get("name"), "content": r.get("outputs"), "is_error": False},
        ) for r in body["tool_results"]]

    results = []
    i = len(messages)
    while i and messages[i - 1].get("role") == "tool":  # OpenAI style
        i -= 1
    for m in messages[i:]:
        results.append({"id": m.get("tool_call_id"), "content": m.get("content"), "is_error": False})

    last = messages[-1] if messages else {}
    if not results and last.get("role") == "user" and isinstance(last.get("content"), list):
        for b in last["content"]:
            if "toolResult" in b:
                r = b["toolResult"]
                results.append({"id": r.get("toolUseId"), "content": r.get("content"), "is_error": r.get("status") == "error"})
            elif b.get("type") == "tool_result":
                results.append({"id": b.get("tool_use_id"), "content": b.get("content"), "is_error": bool(b.get("is_error"))})

    calls = {c["id"]: c for m in messages if m.get("role") == "assistant" for c in tool_calls_in(m)}
    return [(calls.get(r["id"], {"id": r["id"]}), r) for r in results]


def tool_payload(flow, tool_use, request_body=None, response_body=None):
    payload = build_base_payload(flow)
    payload.update({
        "path": "/tools/" + urllib.parse.quote(tool_use.get("name") or "unknown", safe=""),
        "method": "POST",
        "requestHeaders": json.dumps({"host": flow.request.pretty_host}),
        "requestPayload": json.dumps(request_body) if request_body else "{}",
        "responsePayload": json.dumps(response_body) if response_body else "{}",
    })
    return payload


def return_akto_error(flow, validation, phase=None):
    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("         BLOCKED BY AKTO")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(json.dumps(validation, indent=2))
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    reason = block_reason(validation, phase)
    # AWS SDKs surface the body's "message" as the error text.
    body = json.dumps({"message": f"Blocked by Akto: {reason}", "akto": validation})
    flow.response = http.Response.make(
        403,
        body,
        {
            "Content-Type": "application/json",
            "X-Akto-Guardrail": "blocked",
            "X-Akto-Guardrail-Reason": reason
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

    for tool_use, tool_result in tool_results_in_request(flow):
        print(f"\n================ TOOL RESULT: {tool_use.get('name')} ================")
        result_validation = post_json(AKTO_VALIDATE_URL, tool_payload(flow, tool_use, response_body={
            "jsonrpc": "2.0",
            "id": tool_result["id"],
            "result": {"content": tool_result["content"], "isError": tool_result["is_error"]},
        }))
        if is_blocked(result_validation, "responseResult"):
            print(">>> TOOL RESULT BLOCKED BY AKTO")
            return_akto_error(flow, result_validation, "responseResult")
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

    stream = "eventstream" in flow.response.headers.get("content-type", "")
    calls = []
    response_body = flow.response.get_text(strict=False)
    try:
        if stream:
            # Report decoded content, not the binary event-stream frames. Formats
            # with no text/tool parser fall back to the raw decoded events.
            text, calls, events = parse_stream(flow.response.content)
            response_body = json.dumps({"text": text, "toolCalls": calls} if text or calls else events)
        else:
            calls = tool_calls_in(response_message(json.loads(response_body)))
    except Exception as e:
        print(f"[TOOL PARSE ERROR] {e!r}")

    payload["requestHeaders"] = json.dumps({"host": flow.request.pretty_host})
    payload["requestPayload"] = "{}"
    payload["responseHeaders"] = json.dumps(dict(flow.response.headers))
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

    # Checked before the response reaches the Lambda, so a blocked tool call
    # never runs.
    for call in calls:
        print(f"\n================ TOOL CALL: {call['name']} ================")
        call_validation = post_json(AKTO_VALIDATE_URL, tool_payload(flow, call, request_body={
            "jsonrpc": "2.0",
            "id": call["id"],
            "method": "tools/call",
            "params": {"name": call["name"], "arguments": call["input"]},
        }))
        if is_blocked(call_validation, "requestResult"):
            print(">>> TOOL CALL BLOCKED BY AKTO")
            return_akto_error(flow, call_validation, "requestResult")
            return

    modified = modified_payload(response_validation, "responseResult")
    # A plain-text body would corrupt the event stream the SDK expects.
    if modified is not None and not stream:
        print(">>> RESPONSE MODIFIED BY AKTO")
        flow.response.set_text(modified)

    print(">>> RESPONSE ALLOWED")