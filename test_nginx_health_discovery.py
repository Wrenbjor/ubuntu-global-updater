import unittest
from pathlib import Path
from nginx_health_discovery import discover


def dump(main, **files):
    return '# configuration file /etc/nginx/nginx.conf:\n' + main + '\n' + ''.join(
        '# configuration file /etc/nginx/' + path + ':\n' + body + '\n' for path, body in files.items())


class DiscoveryTests(unittest.TestCase):
    def test_embedded_recipe_source_is_identical(self):
        source=Path(__file__).with_name('nginx_health_discovery.py').read_text()
        recipe=Path(__file__).with_name('php85.sh').read_text()
        self.assertIn("NGINX_HEALTH_PY'\n"+source+'NGINX_HEALTH_PY',recipe)

    def test_inline_route_and_default_http(self):
        result = discover(dump('http { server { server_name app.example.com; location / { fastcgi_pass unix:/run/php/app.sock; } } }'))
        self.assertEqual(result[0]['url'], 'http://app.example.com:80/')

    def test_shared_include_associated_with_both_servers(self):
        result = discover(dump('http { server { server_name a.example.com; include php.conf; } server { server_name b.example.com; include php.conf; } }', **{'php.conf': 'fastcgi_pass unix:/run/php/app.sock;'}))
        self.assertEqual([p['host'] for p in result], ['a.example.com', 'b.example.com'])

    def test_first_static_server_not_selected(self):
        result = discover(dump('http { server { server_name static.example.com; return 200; } server { server_name php.example.com; fastcgi_pass unix:/run/php/app.sock; } }'))
        self.assertEqual([p['host'] for p in result], ['php.example.com'])

    def test_listener_sni_and_explicit_address(self):
        result = discover(dump('http { server { listen 10.0.0.5:8443 ssl; server_name app.example.com; fastcgi_pass unix:/run/php/app.sock; } }'))
        self.assertEqual(result[0]['resolve'], 'app.example.com:8443:10.0.0.5')
        self.assertEqual(result[0]['scheme'], 'https')

    def test_ipv6_wildcard(self):
        result = discover(dump('http { server { listen [::]:443 ssl; server_name app.example.com; fastcgi_pass unix:/run/php/app.sock; } }'))
        self.assertEqual(result[0]['resolve'], 'app.example.com:443:[::1]')

    def test_comments_and_quoted_multiline_arguments(self):
        result = discover(dump('http { server { server_name "app.example.com"; # fastcgi_pass bogus;\n fastcgi_pass\n "unix:/run/php/app.sock"; } }'))
        self.assertEqual(result[0]['routes'][0]['arguments'], ['unix:/run/php/app.sock'])

    def test_proxy_protocol_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported health listener'):
            discover(dump('http { server { listen 443 ssl proxy_protocol; server_name app.example.com; fastcgi_pass unix:/run/php/app.sock; } }'))

    def test_wildcard_host_requires_explicit_policy(self):
        with self.assertRaisesRegex(ValueError, 'literal health hostname'):
            discover(dump('http { server { server_name *.example.com; fastcgi_pass unix:/run/php/app.sock; } }'))

    def test_recursion_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Recursive'):
            discover(dump('include nginx.conf;'))

    def test_glob_does_not_cross_directories(self):
        result = discover(dump('http { include sites/*; }', **{'sites/app': 'server { server_name app.example.com; fastcgi_pass unix:/run/php/app.sock; }', 'sites/nested/ignored': 'invalid'}))
        self.assertEqual(len(result), 1)


if __name__ == '__main__':
    unittest.main()
