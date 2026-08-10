import unittest
from fastapi.testclient import TestClient
from api.main import app, PRIVATE_IP_RE

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)

    def test_private_ip_re(self):
        self.assertTrue(PRIVATE_IP_RE.match("http://localhost:8000"))
        self.assertTrue(PRIVATE_IP_RE.match("http://127.0.0.1/test"))
        self.assertTrue(PRIVATE_IP_RE.match("http://10.0.0.1/blog"))
        self.assertFalse(PRIVATE_IP_RE.match("https://www.microsoft.com/security/blog"))

    def test_trigger_invalid_url(self):
        response = self.client.post("/trigger?url=http://127.0.0.1/attack")
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
