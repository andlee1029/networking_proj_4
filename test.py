import requests

ipv4address = "151.101.129.140"
response = requests.get("http://"+ipv4address)
print(response)
print(response.headers)
