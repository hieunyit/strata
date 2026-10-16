import unittest
from header_probe import MARKER, Oracle, classify, request
from http.server import ThreadingHTTPServer
import threading
from urllib.parse import quote


class EvidenceTests(unittest.TestCase):
    def test_http_status_is_not_signature_or_exploit_evidence(self):
        attack = {'malicious': True, 'oracle': True}
        base = {'status': 200, 'oracle': True}
        for status in [200, 400, 403, 418, 429, 500, 502, 503, 504]:
            got = classify(attack, base, {'status': status, 'action': None, 'oracle': False})
            self.assertNotEqual(got, 'signature_block')
            self.assertNotEqual(got, 'backend_sql_oracle_reached')
        self.assertEqual(classify(attack, base, {'status': 200, 'action': 'error', 'oracle': True}), 'inspection_error_reached')
        self.assertEqual(classify(attack, base, {'status': 503, 'action': 'error', 'oracle': False}), 'inspection_error_rejected')
        self.assertEqual(classify(attack, base, {'status': None, 'oracle': None}), 'transport_error')
        self.assertEqual(classify(attack, {'status': 200, 'oracle': False}, {'status': 403, 'action': 'block'}), 'invalid_attack_oracle')

    def test_sql_oracle_executes_query_and_does_not_reflect_arbitrary_text(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Oracle)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            benign = request(server.server_port, '/header-sql', {'X-Example-Filter': '1'})
            self.assertFalse(benign['oracle'])
            sql = "-1 UNION SELECT '"+MARKER+"'--"
            for expression in [sql, quote(sql)]:
                result = request(server.server_port, '/header-sql', {'X-Example-Filter': expression})
                self.assertTrue(result['oracle'], result)
            result = request(server.server_port, '/header-sql', {'X-Example-Filter': MARKER})
            self.assertEqual(result['status'], 400)
            self.assertFalse(result['oracle'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
