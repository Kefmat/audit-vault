"""Integration tests for HTTP REST API."""

import unittest
import json
import urllib.request
import urllib.error
from threading import Thread

from src.storage.memory import MemoryVaultStorage
from src.server import create_server


class TestAuditVaultAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.storage = MemoryVaultStorage()
        cls.api_token = "test-secret-token"
        cls.server = create_server("127.0.0.1", 0, cls.storage, api_token=cls.api_token)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _make_request(self, path: str, method: str = "GET", body: dict = None, token: str = None) -> tuple:
        url = self.base_url + path
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                response_data = json.loads(resp.read().decode("utf-8"))
                return status, response_data
        except urllib.error.HTTPError as err:
            status = err.code
            response_data = json.loads(err.read().decode("utf-8"))
            return status, response_data

    def test_health_check(self):
        status, data = self._make_request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")

    def test_unauthorized_access(self):
        status, data = self._make_request("/v1/audit/events")
        self.assertEqual(status, 401)

    def test_post_event_and_verification(self):
        body = {
            "actor": "user_12345",
            "action": "user.password_reset",
            "target": "user_67890",
            "metadata": {"ip_address": "192.168.1.1"}
        }
        status, data = self._make_request("/v1/audit/events", method="POST", body=body, token=self.api_token)
        self.assertEqual(status, 201)
        self.assertEqual(data["status"], "success")

        # Query events
        status, data = self._make_request("/v1/audit/events", method="GET", token=self.api_token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(data["total"], 1)

        # Verify integrity
        status, data = self._make_request("/v1/audit/verify", method="GET", token=self.api_token)
        self.assertEqual(status, 200)
        self.assertTrue(data["valid"])


if __name__ == "__main__":
    unittest.main()
