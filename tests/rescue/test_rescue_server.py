#!/usr/bin/python3
"""Unit tests for the Rescue R0 authorization boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import sys
import threading
import time
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

    def test_collector_bounds_stdout_and_marks_overflow_failed(self) -> None:
        observation = rescue_server.observe(
            "test.output-limit",
            (sys.executable, "-c", "print('x' * 100000)"),
        )
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertLessEqual(
            len(str(observation["output"]).encode()), rescue_server.MAX_OUTPUT_BYTES
        )

    def test_collector_never_returns_untrusted_stderr(self) -> None:
        observation = rescue_server.observe(
            "test.stderr-separation",
            (
                sys.executable,
                "-c",
                "import sys; print('safe-stdout'); print('private-marker', file=sys.stderr)",
            ),
        )
        self.assertTrue(observation["success"])
        self.assertFalse(observation["truncated"])
        self.assertEqual(observation["output"], "safe-stdout\n")
        self.assertNotIn("private-marker", json.dumps(observation))

    def test_collector_rejects_non_utf8_output_without_expansion(self) -> None:
        observation = rescue_server.observe(
            "test.invalid-utf8",
            (sys.executable, "-c", "import os; os.write(1, bytes([255]) * 40000)"),
        )
        self.assertFalse(observation["success"])
        self.assertFalse(observation["truncated"])
        self.assertEqual(observation["output"], "")

    def test_collector_marks_stderr_overflow_without_exposing_it(self) -> None:
        observation = rescue_server.observe(
            "test.stderr-limit",
            (
                sys.executable,
                "-c",
                "import sys; print('safe'); sys.stderr.write('private-marker' * 10000)",
            ),
        )
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertEqual(observation["output"], "safe\n")
        self.assertNotIn("private-marker", json.dumps(observation))

    def test_collector_kills_descendants_that_keep_pipes_open(self) -> None:
        program = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print('parent-finished')"
        )
        started = time.monotonic()
        with (
            patch.object(rescue_server, "COLLECTOR_TIMEOUT_SECONDS", 0.2),
            patch.object(rescue_server, "COLLECTOR_KILL_GRACE_SECONDS", 0.1),
        ):
            observation = rescue_server.observe(
                "test.inherited-pipe", (sys.executable, "-c", program)
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertEqual(observation["output"], "parent-finished\n")

    def test_inventory_uses_minimized_fixed_collectors(self) -> None:
        commands = dict(rescue_server.COMMANDS)
        self.assertNotIn("linux.fstab", commands)
        lsblk = commands["linux.block.inventory"]
        fields = lsblk[lsblk.index("--output") + 1].split(",")
        self.assertEqual(
            fields,
            [
                "NAME",
                "TYPE",
                "SIZE",
                "RO",
                "FSTYPE",
                "MOUNTPOINTS",
                "SERIAL",
                "WWN",
                "UUID",
                "PARTUUID",
                "PTUUID",
            ],
        )
        self.assertNotIn("MODEL", fields)
        self.assertNotIn("KNAME", fields)
        self.assertNotIn("MAJ:MIN", fields)

    def test_inventory_collectors_run_concurrently(self) -> None:
        barrier = threading.Barrier(len(rescue_server.COMMANDS), timeout=3)
        active = 0
        maximum_active = 0
        counter_lock = threading.Lock()

        def concurrent_observe(
            collector: str, _command: tuple[str, ...]
        ) -> dict[str, object]:
            nonlocal active, maximum_active
            with counter_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                barrier.wait()
            finally:
                with counter_lock:
                    active -= 1
            return {
                "collector": collector,
                "trust": "observed-untrusted",
                "output": "",
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=concurrent_observe):
            observations = rescue_server.inventory()
        self.assertEqual(len(observations), len(rescue_server.COMMANDS))
        self.assertEqual(maximum_active, len(rescue_server.COMMANDS))

    def test_overlapping_inventory_fails_immediately(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        completed: list[list[dict[str, object]]] = []

        def blocked_observe(
            collector: str, _command: tuple[str, ...]
        ) -> dict[str, object]:
            entered.set()
            release.wait(timeout=3)
            return {
                "collector": collector,
                "trust": "observed-untrusted",
                "output": "",
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=blocked_observe):
            worker = threading.Thread(
                target=lambda: completed.append(rescue_server.inventory()), daemon=True
            )
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(rescue_server.InventoryBusy):
                    rescue_server.inventory()
            finally:
                release.set()
                worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(completed), 1)

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

    def test_authorization_rejects_incomplete_identity_inventory(self) -> None:
        observations = [
            {
                "collector": "linux.block.inventory",
                "trust": "observed-untrusted",
                "output": "partial",
                "success": False,
                "truncated": True,
            }
        ]
        with patch.object(rescue_server, "inventory", return_value=observations):
            with self.assertRaisesRegex(rescue_server.BrokerError, "incompleto"):
                rescue_server.authorize_observe(self.request())

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
                "/api/diagnose-linux-p0",
                body="{}",
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "http://127.0.0.1:4173",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 405)
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

    def test_inventory_http_returns_429_while_collection_is_busy(self) -> None:
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        with patch.object(
            rescue_server,
            "inventory",
            side_effect=rescue_server.InventoryBusy("busy"),
        ):
            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "GET",
                "/api/inventory",
                headers={"Host": "127.0.0.1:4173"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 429)
            self.assertEqual(response.getheader("Retry-After"), "1")
            connection.close()

    def test_slow_request_body_is_timed_out(self) -> None:
        with patch.object(rescue_server, "SOCKET_TIMEOUT_SECONDS", 0.1):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = socket.create_connection(server.server_address, timeout=2)
                client.settimeout(2)
                client.sendall(
                    b"POST /api/authorize-observe HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:4173\r\n"
                    b"Origin: http://127.0.0.1:4173\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n{"
                )
                response = bytearray()
                while chunk := client.recv(4096):
                    response.extend(chunk)
                self.assertIn(b" 408 ", response)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_request_has_an_absolute_deadline(self) -> None:
        with (
            patch.object(rescue_server, "SOCKET_TIMEOUT_SECONDS", 2),
            patch.object(rescue_server, "REQUEST_DEADLINE_SECONDS", 0.1),
        ):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = socket.create_connection(server.server_address, timeout=2)
                client.settimeout(2)
                client.sendall(
                    b"POST /api/authorize-observe HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:4173\r\n"
                    b"Origin: http://127.0.0.1:4173\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n{"
                )
                started = time.monotonic()
                try:
                    while client.recv(4096):
                        pass
                except ConnectionResetError:
                    pass
                self.assertLess(time.monotonic() - started, 1)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
