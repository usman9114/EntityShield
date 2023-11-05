"""Anomaly Detection Example"""

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
from joblib import dump
# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix

path_to_mapping = 'assests_mapping/Copy of Updated Mac List(6048).xlsx'
path_to_generic_model_dir = 'model_training/network-model'

def run_dns_model():
    bro_df = pd.read_csv('features-set/dns.csv',error_bad_lines=False)
    bro_df.reset_index(inplace=True)
    bro_df = bro_df[
        ['id.orig_h', 'id.resp_h', 'ts', 'Z', 'id.orig_p', 'id.resp_p', 'proto', 'qtype_name', 'query', 'answers',
         'rejected']].dropna()

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

    import swifter
    bro_df = bro_df[bro_df['proto'].isin(['tcp', 'udp', 'icmp'])]
    bro_df = bro_df[bro_df['rejected'].isin(['T', 'F'])]
    bro_df = bro_df[bro_df['Z'].isin(['0', 'F'])]
    bro_df = bro_df[bro_df['qtype_name'].isin(['A', '*', 'PTR', 'AAAA'])]

    import numpy as np
    print('1. Cleaning/ Validating IP address.....')
    bro_df['id.orig_h'] = bro_df['id.orig_h'].swifter.apply(lambda x: validate_ip(x))
    bro_df['id.resp_h'] = bro_df['id.resp_h'].swifter.apply(lambda x: validate_ip(x))
    bro_df = bro_df[bro_df['id.orig_h'].notna() & bro_df['id.resp_h'].notna()]

    print('3. Generating direction..........')
    bro_df['direction'] = bro_df.swifter.apply(lambda row: traffic_direction(row), axis=1)

    log_type = 'dns'
    features = ['direction', 'Z', 'proto', 'qtype_name', 'id.orig_p', 'id.resp_p', 'query_length', 'answer_length',
                'entropy', 'rejected']
    log_to_df = log_to_dataframe.LogToDataFrame()
    print('Read in {:d} Rows...'.format(len(bro_df)))
    # Using Pandas we can easily and efficiently compute additional data metrics
    # Here we use the vectorized operations of Pandas/Numpy to compute query length
    # We'll also compute entropy of the query
    bro_df['query_length'] = bro_df['query'].str.len()
    bro_df['answer_length'] = bro_df['answers'].str.len()
    bro_df['entropy'] = bro_df['query'].map(lambda x: entropy(x))
    to_matrix = dataframe_to_matrix.DataFrameToMatrix()
    bro_matrix = to_matrix.fit_transform(bro_df[features])
    print(bro_matrix.shape)
    odd_clf = IsolationForest(contamination=0.005, n_jobs=-1, verbose=10)  # Marking 20% as odd
    "d"
    odd_clf.fit(bro_matrix)
    dns_pickle = {'model': odd_clf, 'transformer': to_matrix}

    with open('model_training/network-model/dns_iforest.pkl', 'wb') as pickle_file:
        dump(dns_pickle, pickle_file)