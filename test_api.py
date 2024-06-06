import requests

ENDPOINT = 'http://127.0.0.1:5000/files'

response = requests.get(ENDPOINT)
print(response)

data = response.json()
print(data)

status_code = response.status_code
print(status_code)