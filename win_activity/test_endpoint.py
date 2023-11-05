import requests
import json
with open('conn_anomlay_input.json','r') as f:
    data = f.read()

res = requests.post('localhost:5500/detect-anamaly-conn/network', json=data)
if res.ok:
    print (res.json())