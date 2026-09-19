"""Small HTTP boundary check: browsers cannot cross-site configure credentials."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from http.client import HTTPConnection

spec = importlib.util.spec_from_file_location("assistant_relay_server", Path(__file__).parents[2] / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py")
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)

probe_spec = importlib.util.spec_from_file_location("assistant_ready_probe", Path(__file__).parents[2] / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/assistant_ready_check.py")
probe_module = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe_module)


class AssistantRelayTests(unittest.TestCase):
    def test_readiness_uses_only_local_status_enumeration_and_health(self):
        with patch.object(probe_module, "local_request", side_effect=[
            b'{"ok":true,"harness":"Pi","searchEnabled":true}',
            b'{"ok":true,"adapters":[]}',
            b"OK",
        ]) as request:
            self.assertIsNone(probe_module.check_once())
        self.assertEqual([call.args for call in request.call_args_list], [
            (4173, "/api/rescue/assistant", {"action": "status"}),
            (4173, "/api/rescue/assistant", {"action": "networks"}),
            (8888, "/healthz"),
        ])

    def test_readiness_rejects_failed_network_or_search_without_payloads(self):
        status = b'{"ok":true,"harness":"Pi","searchEnabled":true}'
        for responses, expected in [
            ([b'{"ok":false,"error":"private-detail"}'], "assistant"),
            ([status, b'{"ok":false,"error":"private-detail"}'], "network"),
            ([status, b'{"ok":true,"adapters":[]}', b"not-ready-private-detail"], "search"),
            ([ConnectionRefusedError()], "assistant"),
        ]:
            with self.subTest(expected=expected), patch.object(
                probe_module, "local_request", side_effect=responses
            ):
                self.assertEqual(probe_module.check_once(), expected)

    def test_cross_origin_and_missing_origin_are_denied(self):
        server = server_module.BoundedThreadingHTTPServer(("127.0.0.1", 0), server_module.RescueHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for origin in [None, "https://unrelated.example"]:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                headers = {"Host": "127.0.0.1:8080", "Content-Type": "application/json"}
                if origin:
                    headers["Origin"] = origin
                connection.request("POST", "/api/rescue/assistant", json.dumps({"action": "configure"}), headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
