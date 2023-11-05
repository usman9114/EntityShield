"""Anomaly Detection Example"""
from __future__ import print_function
import os
import warnings
warnings.filterwarnings("ignore")
import swifter
import sys
import argparse
import math
from collections import Counter
import ipaddress

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
# from sklearn.externals import joblib
import joblib
# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix

class dns_anomalyDetect:

    def __init__(self):
        def map_ip_list():
            ip_info = pd.concat(pd.read_excel(os.path.join('Anomaly_detection', 'Copy of Updated Mac List(6048).xlsx'),
                                              sheet_name=None).values())
            hostnames = list(ip_info['Hostname'].values)
            ips = list(ip_info['IP address'].values)
            d = {k: v for k, v in zip(ips, hostnames)}
            return d
        self.features = ['direction','Z', 'proto', 'qtype_name', 'id.orig_p',
                         'id.resp_p', 'query_length', 'answer_length', 'entropy','rejected']
        self.pkl = joblib.load(os.path.join('Anomaly_detection','models', 'dns_iforest.pkl'))
        self.model = self.pkl['model']
        self.transformer = self.pkl['transformer'] # typo fix in next build should be transformer missed  a 's'
        self.d = map_ip_list()


    def entropy(self, string):
        """Compute entropy on the string"""
        try:

            p, lns = Counter(string), float(len(str(string)))
            return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
        except Exception as e:
            pass
            return pd.np.nan

    def traffic_direction(self, conn_row):
        # First try to use the local orig/resp fields
        #     if conn_row.get('local_orig') and conn_row.get('local_resp'):
        #         local_orig = conn_row['local_orig']
        #         local_resp = conn_row['local_resp']
        #     else:
        # Well we don't have local orig/resp fields so use RFC1918 logic
        try:
            local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private
            local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private

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
        except:
            return pd.np.nan

    def ip_embedding_ext(self, ip):
        transformed = None
        try:
            transformed = int(ipaddress.ip_address(ip))
            return transformed
        except:
            return transformed


    def preprocess(self, df):
        df = df[df['proto'].isin(['tcp', 'udp', 'icmp'])]
        df = df[df['Z'].isin([0, 1])]

        df['id.resp_p'] = pd.to_numeric(df['id.resp_p'], errors='coerce')
        df['id.resp_p'] = df['id.resp_p'].fillna(0)

        df['id.orig_p'] = pd.to_numeric(df['id.orig_p'], errors='coerce')
        df['id.orig_p'] = df['id.orig_p'].fillna(0)

        df['query_length'] = df['query'].str.len()
        df['answer_length'] = df['answers'].str.len()
        df['entropy'] = df['query'].map(lambda x: self.entropy(x))
        df['direction'] = df.swifter.apply(lambda row: self.traffic_direction(row), axis=1)

        return df
#
    def load_data(self, data):

        data = data[['id.orig_h','id.resp_h','ts','Z','id.orig_p','id.resp_p', 'proto', 'qtype_name','query','answers','rejected']]
        return data
#
#

    def predict(self, data):
        df = self.load_data(data)
        testset = self.preprocess(df)
        nans = {'Success': False, 'data': df.isna().sum().to_dict()}
        testset = testset.dropna()
        print('After preprocessing '+str(testset.shape[0])+' row remained')
        if testset.shape[0] > 0:
            outputdf = pd.DataFrame()
            to_matrix = dataframe_to_matrix.DataFrameToMatrix()
            bro_matrix = self.transformer.transform(testset[self.features])
            odd_clf = self.model
            predictions = odd_clf.predict(bro_matrix)
            odd_df = testset[self.features][predictions == -1]
            if not odd_df.shape[0] > 0:
                return {'Success': False, 'data': 'No anomaly found'}
            display_df = testset[predictions == -1]
            odd_matrix = to_matrix.fit_transform(odd_df)
            num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
            display_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
            print(odd_matrix.shape)


            cluster_groups = display_df[self.features + ['cluster']+['query','ts','answers','id.orig_h',
                                                                     'id.resp_h']].groupby('cluster')
            # Now print out the details for each cluster
            print('<<< Outliers Detected! >>>')
            for key, group in cluster_groups:
                print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                group = group[['ts', 'id.orig_h', 'id.resp_h', 'Z', 'direction', 'proto', 'qtype_name', 'id.orig_p',
                               'id.resp_p', 'query_length', 'answer_length', 'entropy',
                               'query', 'answers', 'cluster']]

                outputdf = pd.concat([outputdf, group], axis=0)
                outputdf[(outputdf['entropy'] > 2) & (outputdf['entropy'] < 3) ] = None
                outputdf = outputdf.dropna()
            if not outputdf.shape[0] > 0:
                return {'Success': False, 'data': 'No anomaly found'}
            return outputdf.sort_values(by='cluster', ascending=False).reset_index().to_json()
        else:
            return nans


if __name__ =='__main__':
    ad = dns_anomalyDetect()
    print(ad.predict(pd.read_json('inputfile/iesco.json')))

