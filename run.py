from StreamingPhish.service import phishService
from freq_master.freq import FreqCounter
from User_agent.User_agent_detection import detect_single, analyze_user_agents_detect
from Anomaly_detection.conn_wrapper import conn_anomalyDetect
from Anomaly_detection.dns_wrapper import dns_anomalyDetect
from Anomaly_detection.http_wrapper import http_anomalyDetect
from Anomaly_detection.direction import traffic_direction
from uri_checker.malicious_url import uri_check
from scoring.score_endpoints import scoring
from win_activity.suspicious_activity import sysmon_rnn
from safe_browsing.google_check import safebrowseurl
from app_checker.runcheck import AppTest
from app_checker.profile_builder import profileBuilder
from dga.dga_detector import DgaDetect
from Anomaly_detection.real_fast_longConn.zeek_fast_anom import LongConn
from exfil.pcr import PcrModel
from db.db_operations import db_ops
import warnings
import json
warnings.filterwarnings("ignore")
from flask import Flask, request, jsonify, Response
import pandas as pd

from waitress import serve

class Myserver(Flask):
    def __init__(self, name):
        # self.freq = FreqCounter()
        # self.freq_path = 'freq_master/table.freq'
        # self.freq.load(self.freq_path)
        self.conn_ad = conn_anomalyDetect()
        self.fast_ann = LongConn()
        self.dns_ad = dns_anomalyDetect()
        self.http_ad = http_anomalyDetect()
        self.score = scoring()
        self.sb = safebrowseurl()
        self.db_ops = db_ops()
        self.urichecker = uri_check()
        self.sysrnn = sysmon_rnn()
        self.newAppCheck = AppTest()
        self.profileBuild = profileBuilder()
        self.dga_detect = DgaDetect(self.db_ops)
        self.phishing = phishService(self.db_ops)
        self.pcr = PcrModel()

        Flask.__init__(self, name)

my_server = Myserver(__name__)

# accept single user-agent input and returns True/False, Bot-type (if detected)
@my_server.route('/agent-single', methods=['POST', 'GET'])
def user_single():
    if request.method =='POST':
        data = request.data.decode('utf-8')
        return jsonify({'Success': True, 'data': detect_single(data)})
# accept comma separated user-agent list as input and returns True/False, Bot-type (if detected) for each

@my_server.route('/analyze_user_for_traffic',methods=['POST', 'GET'])
def analyze_user_agents():
    # This would return occurrences of abnormal user-agents in a dictionary format
    if request.method =='POST':
        data = request.data.decode('utf-8')
        return jsonify(analyze_user_agents_detect(data))

# DGA detection look for input file in freq_master folder

@my_server.route('/dga', methods=['POST', 'GET'])
def measure():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        entropy, dga = my_server.dga_detect.detect(data)
        return jsonify({'Success': True, 'data': {'entropy': round(entropy), 'DGA': dga}})
    else:
        return jsonify({'Success': False, 'message': 'Method is not post'})

# @my_server.route('/dga', methods=['POST', 'GET'])
# def measure():
#     if request.method == 'POST':
#         data = request.data.decode('utf-8')
#         input=data#pd.read_json(data)
#         dns= my_server.freq.get_domain(input)
#         #my_server.freq.save('freq_master/table.freq')
#         if my_server.freq.probability(dns)[0] > 5:
#             return jsonify({'Success': True, 'data': {'severity': my_server.freq.probability(dns)[0], 'DGA': True}})
#         else:
#             print(dns)
#             return jsonify({'Success': True, 'data': {'severity': my_server.freq.probability(dns)[0], 'DGA': False}})
#     else:
#         return jsonify({'Success': False, 'message': 'Method is not post'})



@my_server.route ('/phishing_whitelst', methods=['GET', 'POST'])
def phish_update():
    try:
        my_server.phishing.update_white_lst()
        return jsonify({'Success':True})
    except Exception as e:
        return jsonify(e)


@my_server.route('/dga_whitelst', methods=['GET','POST'])
def dga_update():
    try:
        my_server.dga_detect.update_white_lst()
        return jsonify({'Success': True})
    except Exception as e:
        return jsonify(e)


#detech uri
@my_server.route('/sysmonrnn', methods=['POST', 'GET'])
def sysmonrnn():
    if request.method == 'POST':
        user = request.args.get('user')
        duration = float(request.args.get('duration'))
        try:
            return jsonify(my_server.sysrnn.predict(user, duration))
        except Exception as e:
            return jsonify({'Success': False, 'error': str(e)})
    else:
        return jsonify({'Success': False, 'message': 'Please send POST request'})

@my_server.route('/uricheck', methods=['POST', 'GET'])
def uri_check():
    if request.method == 'POST':
        try:
            data = request.data.decode("utf-8")
            data = eval(data)
            return jsonify({'Success': True, 'data': my_server.urichecker.predict(data)})
        except Exception as e:
            return jsonify({'Success': False, 'error': str(e)})
    else:
        return jsonify({'Success': False, 'message': 'Please send POST request'})


@my_server.route('/pcr', methods=['POST', 'GET'])
def pcr():
    if request.method == 'POST':
        ip = request.args.get('ip')
        duration = int(request.args.get('duration'))
        try:
            return jsonify({'Success': True, 'data': my_server.pcr.get_pcr(ip, duration)})
        except Exception as e:
            return jsonify({'Success': False, 'error': str(e)})
    else:
        return jsonify({'Success': False, 'message': 'Please send POST request'})



# detect phishing domains
@my_server.route('/phishService', methods=['POST', 'GET'])
def phish():
    if request.method == 'POST':
        try:
            data = request.data.decode("utf-8")
            data = list(data.split(','))
            return jsonify({'Success':True, 'data': my_server.phishing.classify(data)})
        except Exception as e:
            return jsonify({'Success': False, 'data': str(e)})

    else:
        return jsonify({'message':'request method is not post'})


@my_server.route('/safe-browsing', methods=['POST', 'GET'])
def safebrowse():
    if request.method == 'POST':
        try:
            data = request.data.decode('utf-8')
            resp = my_server.sb.lookup_url(url=json.loads(data))
            return jsonify(resp)
        except Exception as e:
            return jsonify({'Success': False, 'data': str(e)})
    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})



@my_server.route('/preprocess', methods=['POST', 'GET'])
def pre_process():
    if request.method == 'POST':
        try:
            data = request.data
            input = pd.read_json(data)
            return my_server.conn_ad.preprocessing(input).reset_index().to_json()
        except Exception as e:
            return str(e)
    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})

@my_server.route('/preprocess-raw', methods=['POST', 'GET'])
def pre_process_raw():
    if request.method == 'POST':
        try:
            data = request.data
            input = pd.read_json(data)
            return my_server.conn_ad.preprocessing(input, non_agg=True).reset_index().to_json()
        except Exception as e:
            return str(e)
    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})


@my_server.route('/app-check/<user>', methods=['GET'])
def app_check(user):
    try:
        return jsonify({'Success': True, 'data': my_server.newAppCheck.run_profile_check(user)})
    except Exception as e:
        return jsonify({'Success': False, 'message': str(e)})

@my_server.route('/build-profile', methods=['GET'])
def app_build_profile():
    try:
        return jsonify({'Success': True, 'data': my_server.profileBuild.build_profile()})
    except Exception as e:
        return jsonify({'Success': False, 'message': str(e)})


# accepts 1-2 hours of connection.logs traffic, return anomalous traffic
# for more details look for input file in anomaly_detection/inputfiles

@my_server.route('/detect-anamaly-conn/<user>', methods=['POST', 'GET'])
def conn_anomaly_detect(user):
    if request.method == 'POST':
        try:
            data = request.data
            input = pd.read_json(data)
            if user != 'network':
                return jsonify({'Success': True, 'data':  my_server.conn_ad.predict(input, user)})

            else:
                return jsonify({'Success': True, 'data':  my_server.conn_ad.predict(input)})
        except Exception as e:
            return jsonify({'Success': False, 'message': str(e)})

    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})


# accepts 1-2 hours of dns.logs traffic, return anomalous traffic
# for more details look for input file in anomaly_detection/inputfiles
@my_server.route('/detect-anamaly-dns', methods=['POST', 'GET'])
def dns_anomaly_detect():
    if request.method == 'POST':
        try:
            data = request.data
            input = pd.read_json(data)
            return jsonify({'Success': True, 'data': my_server.dns_ad.predict(input)})
        except Exception as e:
            return jsonify({'Success': False, 'message': str(e)})




# accepts 1-2 hours of http.logs traffic, return anomalous traffic
# for more details look for input file in anomaly_detection/inputfiles
@my_server.route('/detect-anamaly-http', methods=['POST', 'GET'])
def http_anomaly_detect():
    if request.method == 'POST':
        try:
            data = request.data
            input = pd.read_json(data)
            return jsonify({'Success': True, 'data': my_server.http_ad.predict(input) })

        except Exception as e:
            return jsonify({'Success': False, 'message': str(e)})
    else:
        return jsonify({'Success': False, 'message': 'Please send POST request'})

@my_server.route('/zeek-conn-anom',methods=['GET','POST'])
def zeek_fast_anom():
    try:
        fast_ann = LongConn()
        if fast_ann.get_data_from_sensor():
            return jsonify(fast_ann.detect())
        else:
            return jsonify({'Success': False, 'data': None, 'message': 'unable to fetch data from sensor'})
    except Exception as e:
        return jsonify({'Success': False, 'data': e})



@my_server.route('/risk-top-score',methods=['POST','GET'])
def top_score():
    if request.method == 'POST':
        try:
            return my_server.score.top_n_score().to_json()
        except Exception as e:
            return jsonify(str(e))
    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})


@my_server.route('/traffic-direction/<duration>',methods=['POST','GET'])
def get_direction(duration=10):
    if request.method =='POST':
        try:
            duration = str(duration)+'T'
            data = request.data
            input = pd.read_json(data)
            input['ts'] = pd.to_datetime(input['ts'], unit='ms')
            input.loc[:, 'direction'] = input.apply(lambda row: traffic_direction(row), axis=1)
            input.columns = ['ts', 'SrcAddr', 'DstAddr', 'direction']
            input.set_index(['SrcAddr', 'DstAddr', 'ts'], inplace=True, drop=True)
            group = input.groupby([pd.Grouper(level='SrcAddr'), pd.Grouper(level='DstAddr'),
                                   pd.Grouper(level='ts', freq=duration)])
            direction_vector = group.direction.value_counts().unstack().fillna(0).reset_index().to_json()

            return jsonify({'Success': True, 'data':direction_vector})

        except Exception as e:
            return jsonify(str(e))
    else:
        return jsonify({'Success': False, 'data': 'Please send POST request'})

@my_server.route('/top-risk-user',methods=['POST','GET'])
def get_top_risk():
    try:
        df = my_server.db_ops.fetch_risk_table()
        total_mean = df['total'].mean()
        total_std = df['total'].std()
        df = df.groupby(['ip', 'created_at']).sum().reset_index()
        high_risk_user = set(df[df['total'] > total_mean + total_std]['ip'])
        return jsonify({'Success': True, 'data': {'IP address': list(high_risk_user), 'Count':len(high_risk_user)}})
    except Exception as e:
        return jsonify({'Success': False, 'data': e})


if __name__ == '__main__':
    serve(my_server, host='0.0.0.0', port=5500, cleanup_interval=5000)
    # my_server.run(debug=False, host='0.0.0.0', port=5500, threaded=True)
