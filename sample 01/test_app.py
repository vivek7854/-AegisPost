import json
import unittest
from unittest.mock import patch

import app


class Response:
    def __init__(self, status=200, headers=None, body=b'ok', url='https://public.example/'):
        self.status_code = status
        self.headers = headers or {}
        self.body = body
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        yield self.body


class CheckerTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertEqual(app.validate_url('HTTPS://Example.COM'), 'https://example.com/')
        for url in [
            'ftp://example.com',
            'http://user:pass@example.com',
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                app.validate_url(url)

    def test_private_and_reserved_ranges(self):
        for ip in [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.2',
            '169.254.1.1',
            '224.0.0.1',
            '0.0.0.0',
            '::1',
            'fc00::1',
            'fe80::1',
            'ff02::1',
            '2001:db8::1',
        ]:
            self.assertFalse(app.public_ip(ip), ip)
        self.assertTrue(app.public_ip('8.8.8.8'))

    @patch('app.requests.get')
    @patch('app.resolve_public')
    def test_redirect_revalidates_target(self, resolve, get):
        get.side_effect = [Response(302, {'Location': 'http://127.0.0.1/admin'})]
        with self.assertRaises(ValueError):
            app._request('https://public.example')
        resolve.assert_called_once()
        self.assertEqual(get.call_count, 1)

    @patch('app.requests.get')
    @patch('app.resolve_public')
    def test_redirect_limit(self, resolve, get):
        get.side_effect = [Response(302, {'Location': '/a'}) for _ in range(5)]
        with self.assertRaises(app.CheckError):
            app._request('https://public.example')
        self.assertEqual(get.call_count, 4)

    @patch('app.requests.get')
    @patch('app.resolve_public')
    def test_fixed_file_redirect_cannot_expand_scope(self, resolve, get):
        get.return_value = Response(302, {'Location': '/admin'})
        with self.assertRaisesRegex(app.CheckError, 'outside its allowed path'):
            app._request('https://public.example/robots.txt', redirect_scope=(('https', 'public.example'), '/robots.txt'))
        self.assertEqual(get.call_count, 1)

    @patch.dict('os.environ', {}, clear=True)
    @patch('app.requests.get')
    def test_threat_lookup_without_key_is_unknown(self, get):
        result = app.lookup_threat_intelligence('https://public.example/')
        self.assertEqual(result['status'], 'unknown')
        get.assert_not_called()

    @patch.dict('os.environ', {'GOOGLE_SAFE_BROWSING_API_KEY': 'test-safe-key'})
    @patch('app.requests.get')
    def test_threat_lookup_known_phishing_match(self, get):
        class MockResponse:
            status_code = 200
            def json(self):
                return {'threats': [{'threatTypes': ['SOCIAL_ENGINEERING']}]}

        get.return_value = MockResponse()
        result = app.lookup_threat_intelligence('https://example.test/login')
        self.assertEqual(result['status'], 'match')
        self.assertIn('SOCIAL_ENGINEERING', result['threat_types'])
        self.assertEqual(get.call_args.kwargs['params'][0], ('key', 'test-safe-key'))

    @patch.dict('os.environ', {'GOOGLE_SAFE_BROWSING_API_KEY': 'test-safe-key'})
    @patch('app.requests.get')
    def test_threat_lookup_empty_list_is_not_a_safety_certificate(self, get):
        class MockResponse:
            status_code = 200
            def json(self):
                return {'threats': []}

        get.return_value = MockResponse()
        result = app.lookup_threat_intelligence('https://example.test/')
        self.assertEqual(result['status'], 'no_match')
        self.assertIn('does not prove', result['evidence'])

    @patch.dict('os.environ', {'GOOGLE_SAFE_BROWSING_API_KEY': 'test-safe-key'})
    @patch('app.requests.get')
    def test_threat_lookup_service_error_is_unknown(self, get):
        class MockResponse:
            status_code = 403

        get.return_value = MockResponse()
        self.assertEqual(app.lookup_threat_intelligence('https://example.test/')['status'], 'unknown')

    def test_pdf_download_endpoint_returns_pdf_attachment(self):
        report = {
            'target': 'https://public.example/',
            'assessed_at': '2026-10-27T00:00:00Z',
            'summary': {'score': 50, 'completed': 1, 'total': 2, 'label': 'Review needed', 'badge': 'Needs Attention'},
            'threat_lookup': {
                'status': 'no_match',
                'provider': 'Google Safe Browsing',
                'threat_types': [],
                'evidence': '<script>alert(1)</script> no threat entry returned; this does not prove the site is genuine.',
            },
            'checks': [{
                'title': 'Example header',
                'category': 'Headers',
                'status': 'not_present',
                'evidence': 'Header <script>alert(1)</script> was not observed.',
                'impact': 'A policy can limit risk.',
                'remediation': 'Configure the header.',
                'confidence': 'High',
            }],
            'limitations': 'Passive, single-response review only.',
        }
        response = app.app.test_client().post('/api/report.pdf', json={'report': report})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')
        self.assertIn('attachment; filename=website-posture-report.pdf', response.headers['Content-Disposition'])
        self.assertTrue(response.data.startswith(b'%PDF-'))
        self.assertEqual(response.headers.get('Cache-Control'), 'no-store')

    def test_pdf_download_rejects_invalid_report(self):
        response = app.app.test_client().post('/api/report.pdf', json={'report': {'checks': 'invalid'}})
        self.assertEqual(response.status_code, 400)

    @patch.dict('os.environ', {}, clear=True)
    def test_ai_advice_requires_server_key(self):
        response = app.app.test_client().post('/api/advice', json={'report': {'checks': []}})
        self.assertEqual(response.status_code, 503)
        self.assertIn('OPENAI_API_KEY', response.get_json()['error'])

    @patch.dict('os.environ', {'OPENAI_API_KEY': 'test-secret', 'OPENAI_MODEL': 'test-model'})
    @patch('app.requests.post')
    def test_ai_advice_uses_mocked_api_and_does_not_store(self, post):
        class MockResponse:
            status_code = 200
            def json(self):
                return {'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': 'Prioritize HTTPS improvements.'}]}]}

        post.return_value = MockResponse()
        app.LAST_ADVICE_REQUEST.clear()
        response = app.app.test_client().post(
            '/api/advice',
            json={
                'report': {
                    'target': 'example.test',
                    'summary': {'score': 50},
                    'checks': [{'title': 'TLS', 'status': 'not_present', 'evidence': 'HTTP'}],
                    'secret_extra': 'must not forward',
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('HTTPS', response.get_json()['advice'])
        payload = post.call_args.kwargs['json']
        self.assertFalse(payload['store'])
        self.assertNotIn('secret_extra', payload['input'])
        self.assertNotIn('test-secret', json.dumps(payload))
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer test-secret')

    def test_report_renderer_escapes_user_controlled_fields(self):
        js = __import__('pathlib').Path('static/app.js').read_text(encoding='utf-8-sig')
        self.assertIn('escapeHtml(report.target)', js)
        self.assertIn('escapeHtml(c.evidence)', js)
        self.assertIn('escapeHtml(c.title)', js)

    def test_user_facing_error_state_exists(self):
        html = __import__('pathlib').Path('static/index.html').read_text(encoding='utf-8-sig')
        js = __import__('pathlib').Path('static/app.js').read_text(encoding='utf-8-sig')
        self.assertIn('id="error-message"', html)
        self.assertIn('role="alert"', html)
        self.assertIn('busy) return', js)

    @patch('app.requests.get')
    @patch('app.resolve_public')
    def test_timeout_and_size_limit(self, resolve, get):
        import requests
        get.side_effect = requests.Timeout()
        with self.assertRaisesRegex(app.CheckError, 'time limit'):
            app._request('https://public.example')
        get.side_effect = None
        get.return_value = Response(body=b'x' * 20)
        with self.assertRaisesRegex(app.CheckError, 'larger'):
            app._request('https://public.example', max_bytes=10)

    def test_headers_cookies_and_framing(self):
        checks = app.parse_headers({
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options': 'nosniff',
            'Set-Cookie': 'sid=abc; Secure; HttpOnly; SameSite=Lax',
        })
        states = {c['id']: c['status'] for c in checks}
        self.assertEqual(states['csp'], 'present')
        self.assertEqual(states['framing'], 'present')
        self.assertEqual(states['cookies'], 'present')
        self.assertEqual(states['hsts'], 'not_present')
        self.assertEqual(app.parse_headers({})[-1]['status'], 'not_applicable')

    def test_score_excludes_unknown(self):
        checks = [
            {'weight': 2, 'status': 'present'},
            {'weight': 2, 'status': 'not_present'},
            {'weight': 4, 'status': 'unknown'},
            {'weight': 1, 'status': 'not_applicable'},
        ]
        self.assertEqual(app.score(checks)['score'], 50)
        self.assertEqual(app.score([{'weight': 1, 'status': 'unknown'}])['score'], None)

    @patch('app._request')
    @patch('app.resolve_public')
    def test_api_report_and_no_remote_access(self, resolve, fetch):
        fetch.side_effect = [
            {'status': 200, 'headers': {'X-Frame-Options': 'DENY'}, 'body': b'<html></html>', 'url': 'https://public.example/'},
            {'status': 404, 'headers': {}, 'body': b'', 'url': 'https://public.example/robots.txt'},
            {'status': 404, 'headers': {}, 'body': b'', 'url': 'https://public.example/.well-known/security.txt'},
        ]
        app.LAST_REQUEST.clear()
        client = app.app.test_client()
        response = client.post('/api/check', json={'url': 'https://public.example'})
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report['target'], 'https://public.example/')
        self.assertEqual(fetch.call_count, 3)
        self.assertTrue(all(x['evidence'] for x in report['checks']))

    def test_framing_never_claims_observation_without_control(self):
        result = next(c for c in app.parse_headers({}) if c['id'] == 'framing')
        self.assertEqual(result['status'], 'not_present')
        self.assertIn('No X-Frame-Options', result['evidence'])

    @patch.dict('os.environ', {'GEMINI_API_KEY': 'fake-gemini-key', 'GEMINI_MODEL': 'gemini-1.5-flash'})
    @patch('app._call_gemini_api')
    def test_gemini_advice_integration(self, mock_gemini):
        mock_gemini.return_value = '### Gemini Automated Defensive Advice\n1. Enforce HSTS.'
        app.LAST_ADVICE_REQUEST.clear()
        client = app.app.test_client()
        response = client.post('/api/advice', json={'report': {'target': 'https://example.com', 'checks': []}})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('Gemini', data['provider'])
        self.assertIn('HSTS', data['advice'])

    @patch.dict('os.environ', {'GROQ_API_KEY': 'fake-groq-key', 'GROQ_MODEL': 'llama-3.3-70b-versatile'})
    @patch('app._call_groq_api')
    def test_groq_advice_integration(self, mock_groq):
        mock_groq.return_value = '### Groq High-Speed Remediation Advice\n1. Configure CSP.'
        app.LAST_ADVICE_REQUEST.clear()
        client = app.app.test_client()
        response = client.post('/api/advice', json={'report': {'target': 'https://example.com', 'checks': []}})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('Groq', data['provider'])
        self.assertIn('CSP', data['advice'])

    def test_fix_snippet_generator(self):
        client = app.app.test_client()
        response = client.post('/api/fix-snippet', json={'server': 'nginx', 'missing': ['hsts', 'csp']})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('add_header Strict-Transport-Security', data['snippet'])
        self.assertIn('add_header Content-Security-Policy', data['snippet'])

    def test_explain_security_concept(self):
        client = app.app.test_client()
        response = client.post('/api/explain', json={'id': 'csp'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('Content Security Policy', data['title'])
        self.assertIn('analogy', data)
        self.assertIn('simple_explanation', data)

    def test_health_endpoint(self):
        client = app.app.test_client()
        response = client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
