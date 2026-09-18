"""Small HTTP boundary check: browsers cannot cross-site configure credentials."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.client import HTTPConnection

spec = importlib.util.spec_from_file_location("assistant_relay_server", Path(__file__).parents[2] / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py")
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)


class AssistantRelayTests(unittest.TestCase):
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
