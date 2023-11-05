import requests
import json
from os import path

'''
This is for testing anomaly detection models
'''
anomaly_files_path_conn = path.join('Anomaly_detection', 'inputfile', 'Anamoly_test.json')
anomaly_files_path_dns = path.join('Anomaly_detection', 'inputfile', 'sampl.json')
anomaly_files_path_http = path.join('Anomaly_detection', 'inputfile', 'http_test.json')

DGA = path.join('freq_master', 'data', 'input', 'input.txt')
phis = path.join('StreamingPhish', 'data', 'input.txt')
useragent = path.join('User_agent', 'input', 'multiple.txt')


# for anomaly detection
path_list = {anomaly_files_path_conn:'/detect-anamaly-conn',
             anomaly_files_path_dns:'/detect-anamaly-dns',
             anomaly_files_path_http:'/detect-anamaly-http',
             }

# for dga phishing and useragent
path_list1 = { DGA:'/measure',phis:'/phishService', useragent:'/analyze_user_for_traffic'}

for i, v in path_list.items():
    print(i)
    try:
        with open(i) as f:
            data = json.load(f)

        response = requests.post('http://127.0.0.1:5500'+v, json=data)

        if response.status_code == 200:
            print('Success')
            print("Status code: ", response.status_code)
            response_Json = response.json()
            print("Printing Post JSON data")
            print(response_Json)
            print('\n\n')

    except Exception as e:
            pass

for i,v in path_list1.items():
    with open(i) as f:
        data = f.read()

    response = requests.post('http://127.0.0.1:5500'+v, data=data)
    if response.status_code == 200:
        print('Success')
        print("Status code: ", response.status_code)
        print("Printing Post JSON data")
        print(response.content)
        print('\n\n')
