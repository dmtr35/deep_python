import urllib.parse
import urllib.request

url = 'https://www.nostarch.com'

info = {'user': 'tim', 'passwd': '31337'}
data = urllib.parse.urlencode(info).encode()
# теперь данные имеют тип bytes

req = urllib.request.Request(url, data)
with urllib.request.urlopen(req) as response: # POST
    content = response.read()
    
print(content)