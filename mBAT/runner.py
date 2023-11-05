from consolidate.consolidate_script import run
from model_training.model_generation_simple import model_run
from model_training.model_generation_simple_dns import run_dns_model
from model_training.model_generation_simple_http import run_http_model
import argparse

parser = argparse.ArgumentParser(description='MBAT "Micro Behaviour Analytics Tool by -Usman Qureshi"')
parser.add_argument('-l', '--logs', help='path to bro logs folder', required=False)
args = vars(parser.parse_args())

run(args['logs'])
model_run()
run_dns_model()
run_http_model()
# from subprocess import call
#
# cmd = "scp -3 root@172.16.4.23:/usr/local/bro/Automated_Anomaly/user-model/user_conn_v0.1.pkl ctguser1@172.16.4.78:/home/ctguser1/cogito-ml/ML/Anomaly_detection/models/user_conn_v0.1.pkl"
# call(cmd.split(" "))
# cmd = "scp -3 root@172.16.4.23:/usr/local/bro/Automated_Anomaly/network-model/generic_conn_v0.1.pkl ctguser1@172.16.4.78:/home/ctguser1/cogito-ml/ML/Anomaly_detection/models/generic_conn_v0.1.pkl"
# call(cmd.split(" "))
# cmd = "scp -3 root@172.16.4.23:/usr/local/bro/Automated_Anomaly/network-model/http_ifroest.pkl ctguser1@172.16.4.78:/home/ctguser1/cogito-ml/ML/Anomaly_detection/models/http_ifroest.pkl"
# call(cmd.split(" "))
# cmd = "scp -3 root@172.16.4.23:/usr/local/bro/Automated_Anomaly/network-model/dns_iforest.pkl ctguser1@172.16.4.78:/home/ctguser1/cogito-ml/ML/Anomaly_detection/models/dns_iforest.pkl"