import unittest
from header_probe import MARKER, Oracle, classify, request
from header_xss_browser_probe import Reflector
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


class BrowserOracleInputTests(unittest.TestCase):
    def test_rejects_invalid_decoding_context_and_oversized_input(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Reflector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for uri, value in [('/reflect?e=2', 'x'), ('/reflect?c=3', 'x'),
                               ('/reflect?e=1', '!not-base64'), ('/reflect?e=1', '/w==')]:
                with self.subTest(uri=uri, value=value):
                    self.assertEqual(request(server.server_port, uri, {'X-Example-Text': value})['status'], 400)
            self.assertEqual(request(server.server_port, '/reflect', {'X-Example-Text': 'x' * 8193})['status'], 413)
            self.assertEqual(request(server.server_port, '/reflect?' + 'x' * 1025, {})['status'], 413)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
