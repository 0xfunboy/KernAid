#!/usr/bin/python3
"""Unit tests for the Rescue R0 authorization boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from http.client import HTTPConnection
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

SERVER = (
    Path(__file__).parents[2]
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py"
)
SPEC = spec_from_file_location("kernaid_rescue_server", SERVER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Rescue server")
rescue_server = module_from_spec(SPEC)
SPEC.loader.exec_module(rescue_server)

FINGERPRINT = "sha256:" + "1" * 64


class ObserveBrokerTests(unittest.TestCase):
    def request(self, **changes: object) -> dict[str, object]:
        request: dict[str, object] = {
            "sessionId": "S-test",
            "planId": "P-test",
            "targetFingerprint": FINGERPRINT,
            "sequence": 1,
            "action": "system.observe.noop",
        }
        request.update(changes)
        return request

    def test_accepts_only_the_allowlisted_action_once(self) -> None:
        broker = rescue_server.ObserveBroker(FINGERPRINT)
        broker.authorize(self.request())
        with self.assertRaisesRegex(rescue_server.BrokerError, "fuori sequenza"):
            broker.authorize(self.request())
        with self.assertRaisesRegex(rescue_server.BrokerError, "non consentita"):
            broker.authorize(self.request(action="shell.exec", sequence=2))

    def test_collector_drains_but_retains_only_bounded_output(self) -> None:
        observation = rescue_server.observe(
            "test.output-limit",
            (sys.executable, "-c", "print('x' * 100000)"),
        )
        self.assertTrue(observation["success"])
        self.assertLessEqual(
            len(str(observation["output"]).encode()), rescue_server.MAX_OUTPUT_BYTES
        )

    def test_rejects_stale_or_malformed_targets(self) -> None:
        broker = rescue_server.ObserveBroker(FINGERPRINT)
        with self.assertRaisesRegex(rescue_server.BrokerError, "target è cambiato"):
            broker.authorize(self.request(targetFingerprint="sha256:" + "2" * 64))
        with self.assertRaisesRegex(rescue_server.BrokerError, "non valida"):
            broker.authorize(self.request(targetFingerprint="invalid"))

    def test_authorization_recollects_inventory_at_the_boundary(self) -> None:
        observations = [
            {
                "collector": "system.hostname",
                "trust": "observed-untrusted",
                "output": "host\n",
                "success": True,
            }
        ]
        fingerprint = rescue_server.inventory_fingerprint(observations)
        rescue_server.BROKERS.clear()
        with patch.object(rescue_server, "inventory", return_value=observations):
            rescue_server.authorize_observe(
                self.request(targetFingerprint=fingerprint, sessionId="S-boundary")
            )

    def test_changed_inventory_invalidates_an_existing_session(self) -> None:
        before = [
            {
                "collector": "system.hostname",
                "trust": "observed-untrusted",
                "output": "before\n",
                "success": True,
            }
        ]
        after = [{**before[0], "output": "after\n"}]
        fingerprint = rescue_server.inventory_fingerprint(before)
        rescue_server.BROKERS.clear()
        with patch.object(rescue_server, "inventory", side_effect=[before, after]):
            rescue_server.authorize_observe(
                self.request(targetFingerprint=fingerprint, sessionId="S-changing")
            )
            with self.assertRaisesRegex(rescue_server.BrokerError, "target è cambiato"):
                rescue_server.authorize_observe(
                    self.request(
                        targetFingerprint=fingerprint,
                        sessionId="S-changing",
                        sequence=2,
                    )
                )

    def test_http_boundary_rejects_host_and_origin_attacks(self) -> None:
        observations = [
            {
                "collector": "system.hostname",
                "trust": "observed-untrusted",
                "output": "host\n",
                "success": True,
            }
        ]
        fingerprint = rescue_server.inventory_fingerprint(observations)
        request = json.dumps(
            self.request(
                sessionId="S-http",
                planId="P-http",
                targetFingerprint=fingerprint,
            )
        )
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        with patch.object(rescue_server, "inventory", return_value=observations):
            connection = HTTPConnection("127.0.0.1", port)
            connection.request("GET", "/api/inventory", headers={"Host": "attacker.invalid"})
            self.assertEqual(connection.getresponse().status, 421)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "GET",
                "/api/inventory",
                headers={
                    "Host": "127.0.0.1:4173",
                    "Sec-Fetch-Site": "cross-site",
                },
            )
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/authorize-observe",
                body=request,
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "https://attacker.invalid",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/authorize-observe",
                body=request,
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "http://127.0.0.1:4173",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 200)
            connection.close()


if __name__ == "__main__":
    unittest.main()
