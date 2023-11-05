
from __future__ import print_function
from IPython.display import display, HTML

from matplotlib import pyplot as plt
import os
import sys
import argparse
import math
from collections import Counter
import ipaddress
import seaborn as sns
# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix
import joblib
import numpy as np
path_to_mapping = 'assests_mapping/Copy of Updated Mac List(6048).xlsx'
path_to_generic_model_dir = 'model_training/network-model'
def run_http_model():

    bro_df = pd.read_csv('features-set/http.csv',error_bad_lines=False)
    bro_df = bro_df[['ts','id.orig_h','id.resp_h','id.orig_p','id.resp_p', 'method', 'resp_mime_types', 'request_body_len','host','uri']].dropna()

    bro_log = 'http'


    def map_ip_list(path):
        ip_info = pd.concat(pd.read_excel(path, sheet_name=None).values())
        host_names = list(ip_info['Hostname'].values)
        ips = list(ip_info['IP address'].values)
        d = {k: v for k, v in zip(ips, host_names)}
        return d


    d = map_ip_list(path_to_mapping)  # dict


    def entropy(string):
        """Compute entropy on the string"""
        try:
            p, lns = Counter(string), float(len(string))
            return -sum(count / lns * math.log(count / lns, 2) for count in p.values())
        except Exception as e:
            return pd.np.nan


    def traffic_direction(conn_row):
        # First try to use the local orig/resp fields
        #     if conn_row.get('local_orig') and conn_row.get('local_resp'):
        #         local_orig = conn_row['local_orig']
        #         local_resp = conn_row['local_resp']
        #     else:
        # Well we don't have local orig/resp fields so use RFC1918 logic
        local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private or conn_row['id.orig_h'] in d.keys()
        local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private or conn_row['id.resp_h'] in d.keys()

        # Determine north/south or internal traffic
        if (not local_orig) and local_resp:
            return 'incoming'
        if local_orig and not local_resp:
            return 'outgoing'

        # Neither host is in the allocated private ranges
        if ipaddress.ip_address(conn_row['id.orig_h']).is_multicast or \
                ipaddress.ip_address(conn_row['id.resp_h']).is_multicast:
            return 'multicast'

        # Both hosts are internal
        return 'internal'


    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return ip
        except:
            return np.nan

    if bro_log:
        bro_log = os.path.expanduser(bro_log)
        # Sanity check either http or dns log
        if 'http' in bro_log:
            log_type = 'http'
            features = ['method', 'resp_mime_types', 'request_body_len','direction']
        elif 'dns' in bro_log:
            log_type = 'dns'
            features = ['Z', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy']
        else:
            print('This example only works with Zeek with http.log or dns.log files..')
            sys.exit(1)

        # Create a Pandas dataframe from a Zeek log
        try:
            log_to_df = log_to_dataframe.LogToDataFrame()
            #bro_df = pd.read_csv('http_Farrukh-Naveed-Anjum.csv')#log_to_df.create_dataframe(bro_log)
            #print(bro_df.head())
        except IOError:
            print('Could not open or parse the specified logfile: %s' % bro_log)
            sys.exit(1)
        print('Read in {:d} Rows...'.format(len(bro_df)))

        print('1. Cleaning/ Validating IP address.....')
        bro_df['id.orig_h'] = bro_df['id.orig_h'].apply(lambda x: validate_ip(x))
        bro_df['id.resp_h'] = bro_df['id.resp_h'].apply(lambda x: validate_ip(x))
        bro_df = bro_df[bro_df['id.orig_h'].notna() & bro_df['id.resp_h'].notna()]
        bro_df['request_body_len'] = pd.to_numeric(bro_df['request_body_len'], errors='coerce')
        print('3. Generating direction..........')
        bro_df['direction'] = bro_df.apply(lambda row: traffic_direction(row), axis=1)

        # Using Pandas we can easily and efficiently compute additional data metrics
        # Here we use the vectorized operations of Pandas/Numpy to compute query length
        # We'll also compute entropy of the query
        if log_type == 'dns':
            bro_df['query_length'] = bro_df['query'].str.len()
            bro_df['answer_length'] = bro_df['answers'].str.len()
            bro_df['entropy'] = bro_df['query'].map(lambda x: entropy(x))
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        bro_matrix = to_matrix.fit_transform(bro_df[features])
        print(bro_matrix.shape)



    odd_clf = IsolationForest(contamination=0.05, n_jobs=-1,verbose=3)  # Marking 20% as odd
    odd_clf.fit(bro_matrix)

    http_pickle = {'model': odd_clf, 'transformer': to_matrix}

    with open(path_to_generic_model_dir+'/http_ifroest.pkl', 'wb') as pickle_file:
        joblib.dump(http_pickle, pickle_file)
if __name__ =='__main__':
    run_http_model()




