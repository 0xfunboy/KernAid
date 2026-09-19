#!/usr/bin/python3
"""QEMU readiness check of the running local assistant, relay and search service."""

from http.client import HTTPConnection, HTTPException
import json
import time


UI_PORT = 4173
SEARCH_PORT = 8888
READY = "KERNAID_RESCUE_ASSISTANT_READY_V1 relay=unix network=enumerated search=local ready=true"


def local_request(port, path, payload=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers = {
                "Origin": f"http://127.0.0.1:{port}",
                "Content-Type": "application/json",
            }
        connection.request("GET" if body is None else "POST", path, body, headers)
        response = connection.getresponse()
        data = response.read(65537)
        if response.status != 200 or len(data) > 65536:
            raise ValueError("invalid local response")
        return data
    finally:
        connection.close()


def check_once():
    stage = "assistant"
    try:
        # The real HTTP relay reaches the Unix socket under the UI service's
        # identity. This checks its group access too, unlike a root socket probe.
        status = json.loads(local_request(UI_PORT, "/api/rescue/assistant", {"action": "status"}))
        if not isinstance(status, dict) or status.get("ok") is not True or status.get("harness") != "Pi" or status.get("searchEnabled") is not True:
            raise ValueError("assistant not ready")
        stage = "network"
        networks = json.loads(local_request(UI_PORT, "/api/rescue/assistant", {"action": "networks"}))
        if not isinstance(networks, dict) or networks.get("ok") is not True or not isinstance(networks.get("adapters"), list):
            raise ValueError("network enumeration failed")
        # QEMU -nic none legitimately enumerates an empty list. No adapter is
        # configured, no key is required, and no request leaves the machine.
        stage = "search"
        if local_request(SEARCH_PORT, "/healthz") != b"OK":
            raise ValueError("search not ready")
    except (OSError, HTTPException, ValueError):
        return stage
    return None


def main():
    deadline = time.monotonic() + 60
    stage = "assistant"
    while time.monotonic() < deadline:
        stage = check_once()
        if stage is None:
            print("\n" + READY, flush=True)
            return 0
        time.sleep(1)
    # Never echo local payloads: status may describe user-selected endpoints.
    print(f"\nKERNAID_RESCUE_ASSISTANT_FAILURE_V1 stage={stage}", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
