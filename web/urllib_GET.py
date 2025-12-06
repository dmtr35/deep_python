import urllib.parse
import urllib.request

url = 'https://www.nostarch.com'
with urllib.request.urlopen(url) as response:
    content = response.read()

print(content)