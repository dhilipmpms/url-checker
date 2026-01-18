from urllib.parse import urlparse
import re

def test_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(":")[0]
    print(f"URL: '{url}' -> Scheme: '{parsed_url.scheme}', Netloc: '{parsed_url.netloc}', Domain: '{domain}'")

test_url("google.com")
test_url("https://google.com")
test_url("https://www.1337x.to/u")
