"""Anomaly Detection Example"""
from __future__ import print_function

import os
import sys
import argparse
import math
from collections import Counter
import ipaddress
import numpy as np
# Third Party Imports
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
import joblib
import swifter
# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix
from zat import log_to_dataframe

class conn_anomalyDetect:

    def __init__(self):

        def map_ip_list():
            ip_info = pd.concat(pd.read_excel(os.path.join('Anomaly_detection','Copy of Updated Mac List(6048).xlsx'), sheet_name=None).values())
            hostnames = list(ip_info['Hostname'].values)
            ips = list(ip_info['IP address'].values)
            d = {k: v for k, v in zip(ips, hostnames)}
            return d

        self.features = ['netflows', 'TotDur', 'minDur', 'maxDur', 'tcp', 'udp', 'internal', 'incoming', 'outgoing', 'http',
                        'dns', 'dhcp', 'ssl', 'ssh', 'Totbytes', 'Totpackets', 'packetImbalance', 'byteImbalance', 'DayofWeek', 'isClient']

        self.network_pkl = joblib.load(os.path.join('Anomaly_detection', 'models', 'network-model', 'generic_conn_v0.1.pkl'))
        self.user_pkl = joblib.load(os.path.join('Anomaly_detection', 'models', 'user-model', 'user_conn_v0.1.pkl'))

        self.model_network = self.network_pkl['model']

        self.transformer = self.network_pkl['transformer']  # typo fix in next build should be transformer missed  a 's'
        self.d = map_ip_list()
    #

    def private_ip(self, src_ip, dest_ip):
        if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(src_ip).is_multicast or src_ip in self.d.keys():
            return src_ip
        elif ipaddress.ip_address(dest_ip).is_private or ipaddress.ip_address(
                dest_ip).is_multicast or dest_ip in self.d.keys():
            return dest_ip
        else:
            return np.nan

    def client_server(self, src_ip, dest_ip):
        if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(src_ip).is_multicast or src_ip in self.d.keys():
            return 'client'
        elif ipaddress.ip_address(dest_ip).is_private or ipaddress.ip_address(
                dest_ip).is_multicast or dest_ip in self.d.keys():
            return 'server'
        else:
            return np.nan

    def getFeatures(self, df):
        df = self.preprocessing(df)
        df['ts'] = pd.to_datetime(df['ts'])
        df.set_index(['SrcAddr', 'DstAddr', 'ts', 'id.resp_p'], inplace=True, drop=True)
        group = df.groupby([pd.Grouper(level='SrcAddr'), pd.Grouper(level='DstAddr'), pd.Grouper(level='id.resp_p'),
                            pd.Grouper(level='ts', freq='10T')])

        # df_win.groupby(['SrcAddr'])
        #         train_win = group.Dport.nunique()
        train_win = pd.DataFrame()
        # train_win['udest_ip'] = group.DstAddr.nunique()
        #         train_win['udest_port'] = group.Dport.nunique()
        train_win['netflows'] = group.Dport.count()
        #         train_win['uproto'] = group.Proto.nunique()
        train_win['TotDur'] = group.Dur.sum()
        train_win['minDur'] = group.Dur.min()
        train_win['maxDur'] = group.Dur.max()
        train_win['orig_pkts'] = group['orig_pkts'].sum()
        train_win['resp_pkts'] = group['resp_pkts'].sum()

        train_win['resp_bytes'] = group['resp_bytes'].sum()
        train_win['orig_bytes'] = group['orig_bytes'].sum()

        temp = group.Proto.value_counts().unstack().fillna(0)
        try:
            train_win['tcp'] = temp['tcp']
        except:
            train_win['tcp'] = group.Dport.count() * 0
        try:
            train_win['udp'] = temp['udp']
        except:
            train_win['udp'] = group.Dport.count() * 0

        temp = group.dir.value_counts().unstack().fillna(0)
        try:
            train_win['internal'] = temp['internal']
        except:
            train_win['internal'] = 0
        try:
            train_win['incoming'] = temp['incoming']
        except:
            train_win['incoming'] = 0
        try:
            train_win['outgoing'] = temp['outgoing']
        except:
            train_win['outgoing'] = 0
        try:
            train_win['multicast'] = temp['multicast']
        except:
            train_win['multicast'] = 0

        temp = group.service.value_counts().unstack().fillna(0)
        try:
            train_win['http'] = temp['http']
        except:
            train_win['http'] = 0
        try:
            train_win['dns'] = temp['dns']
        except:
            train_win['dns'] = 0
        try:
            train_win['dhcp'] = temp['dhcp']
        except:
            train_win['dhcp'] = 0
        try:
            train_win['ssl'] = temp['ssl']
        except:
            train_win['ssl'] = 0
        try:
            train_win['ssh'] = temp['ssh']
        except:
            train_win['ssh'] = 0

        train_win['Totbytes'] = train_win['resp_bytes'] + train_win['orig_bytes']
        train_win['Totpackets'] = train_win['orig_pkts'] + train_win['resp_pkts']

        train_win['packetImbalance'] = (train_win['orig_pkts'] - train_win['resp_pkts']) / (
                    train_win['orig_pkts'] + train_win['resp_pkts'])
        train_win['byteImbalance'] = (train_win['orig_bytes'] - train_win['resp_bytes']) / (
                    train_win['orig_bytes'] + train_win['resp_bytes'])

        del train_win['orig_pkts']
        del train_win['resp_pkts']
        del train_win['resp_bytes']
        del train_win['orig_bytes']
        # train_win['Label'] = (group.Label.sum()*1.0/group.Dport.count())> 0
        #         trainX = pd.concat([trainX, train_win], axis=0)
        train_win['DayofWeek'] = [f[3].day_name() for f in train_win.index]
        train_win['privateIP'] = [self.private_ip(f[0], f[1]) for f in train_win.index]
        train_win['isClient'] = [self.client_server(f[0], f[1]) for f in train_win.index]
        return train_win.round(2)



    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return ip
        except:
            return np.nan

    def traffic_direction(self, conn_row):
        # First try to use the local orig/resp fields
        #     if conn_row.get('local_orig') and conn_row.get('local_resp'):
        #         local_orig = conn_row['local_orig']
        #         local_resp = conn_row['local_resp']
        #     else:
        # Well we don't have local orig/resp fields so use RFC1918 logic
        local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private or conn_row['id.orig_h'] in self.d.keys()
        local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private or conn_row['id.resp_h'] in self.d.keys()

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

    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return ip
        except:
            return np.nan


    def preprocessing(self, bro_df):
        bro_df = bro_df[bro_df['service'].isin(['http', 'dns', 'dhcp', 'ssl', 'ssh'])]
        bro_df.loc[:, 'orig_bytes'] = pd.to_numeric(bro_df.loc[:, 'orig_bytes'], errors='coerce')
        bro_df.loc[:, 'orig_bytes'] = bro_df.loc[:, 'orig_bytes'].fillna(0)

        # print('2. Cleaning/ Validating IP address.....')
        bro_df.loc[:, 'id.orig_h'] = bro_df.loc[:, 'id.orig_h'].apply(lambda x: self.validate_ip(x))
        bro_df.loc[:, 'id.resp_h'] = bro_df.loc[:, 'id.resp_h'].apply(lambda x: self.validate_ip(x))
        bro_df = bro_df[bro_df.loc[:, 'id.orig_h'].notna() & bro_df.loc[:, 'id.resp_h'].notna()]

        # print('TS to Timestamp format')
        bro_df.loc[:, 'ts'] = pd.to_datetime(bro_df['ts'])
        # print('2. Assinging Names to IP address.....')
        # bro_df['Hostname_orig'] = bro_df['id.orig_h'].apply(lambda x : d.get(x,np.nan))
        # bro_df['Hostname_resp'] = bro_df['id.resp_h'].apply(lambda x : d.get(x,np.nan))

        # print('3. Generating direction..........')
        bro_df.loc[:, 'direction'] = bro_df.apply(lambda row: self.traffic_direction(row), axis=1)

        # print('5. Cleansing resp bytes')
        bro_df.loc[:, 'resp_bytes'] = pd.to_numeric(bro_df.loc[:, 'resp_bytes'], errors='coerce')
        bro_df.loc[:, 'resp_bytes'] = bro_df.loc[:, 'resp_bytes'].fillna(0)

        # print('6. Cleansing resp packets')
        bro_df.loc[:, 'resp_pkts'] = pd.to_numeric(bro_df['resp_pkts'], errors='coerce')
        bro_df.loc[:, 'resp_pkts'] = bro_df.loc[:, 'resp_pkts'].fillna(0)

        # print('7. Cleansing orig_ip_bytes ')
        bro_df.loc[:, 'orig_ip_bytes'] = pd.to_numeric(bro_df.loc[:, 'orig_ip_bytes'], errors='coerce')
        bro_df.loc[:, 'orig_ip_bytes'] = bro_df.loc[:, 'orig_ip_bytes'].fillna(0)

        # print('8. Cleansing resp_ip_bytes ')
        bro_df.loc[:, 'resp_ip_bytes'] = pd.to_numeric(bro_df.loc[:, 'resp_ip_bytes'], errors='coerce')
        bro_df.loc[:, 'resp_ip_bytes'] = bro_df.loc[:, 'resp_ip_bytes'].fillna(0)

        # print('9. Cleansing id.resp_p')
        bro_df.loc[:, 'id.resp_p'] = pd.to_numeric(bro_df.loc[:, 'id.resp_p'], errors='coerce')
        bro_df.loc[:, 'id.resp_p'] = bro_df['id.resp_p'].fillna(0)

        # print('10. Cleansing id.orig_p')
        bro_df.loc[:, 'id.orig_p'] = pd.to_numeric(bro_df.loc[:, 'id.orig_p'], errors='coerce')
        bro_df.loc[:, 'id.orig_p'] = bro_df.loc[:, 'id.orig_p'].fillna(0)

        # print('11. Converting Duration to Seconds')
        bro_df.loc[:, 'durationsec'] = pd.to_numeric(bro_df.duration, errors='coerce')
        bro_df.loc[:, 'durationsec'] = bro_df.loc[:, 'durationsec'].fillna(0)

        bro_df = bro_df[['ts', 'id.orig_h', 'uid', 'id.resp_h', 'proto', 'id.resp_p', 'id.orig_p', 'durationsec',
                         'direction', 'service', 'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']]

        bro_df.columns = ['ts', 'SrcAddr', 'session_id', 'DstAddr', 'Proto', 'Dport', 'Sport', 'Dur', 'dir', 'service',
                          'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']  # or id.orig_p ? not sure

        # bro_df['id.orig_h_e']=bro_df['id.orig_h'].apply(lambda x : ip_embedding_ext(x))

        return bro_df
#
    def load_data(self, data):

        #data = pd.read_csv(os.path.join('../IESCO_dec_feb', 'conn.csv'))
        data = data[['ts', 'id.orig_h', 'duration', 'id.resp_h', 'orig_bytes','orig_pkts',
                           'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                           'service', 'proto']]
        print('input rows', data.shape)
        return data
#
#

    def predict(self, df, user=None):
        #df = self.load_data(data)
        if df.shape[0] < 1000:
            return {'Success': False, 'data': 'At least 1000 must be passed '}
        nans = {'Success': False, 'data': df.isna().sum().to_dict()}
        df = df.dropna()
        if df.shape[0] < 100:
            return nans
        testset = self.getFeatures(df)
        if testset.shape[0] > 0:
            outputdf = pd.DataFrame()
            to_matrix = dataframe_to_matrix.DataFrameToMatrix()
            bro_matrix = self.transformer.transform(testset[self.features])
            if user:
                try:
                    odd_clf = self.user_pkl[user]
                except:
                    print('User not found')
                    odd_clf = self.model_network
            else:
                odd_clf = self.model_network
            predictions = odd_clf.predict(bro_matrix)
            odd_df = testset[self.features][predictions == -1]
            if not odd_df.shape[0] > 0:
                return {'Success': False, 'data': 'No anomaly found'}
            display_df = testset[predictions == -1]
            odd_matrix = to_matrix.fit_transform(odd_df)
            num_clusters = min(len(odd_df), 4)  # 4 clusters unless we have less than 4 observations
            display_df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(odd_matrix)
            print(odd_matrix.shape)
            # self.features += ['id.orig_h']
            # self.features += ['ts']
            # self.features += ['id.resp_h']
            cluster_groups = display_df[self.features + ['cluster']].groupby('cluster')
            # Now print out the details for each cluster
            print('<<< Outliers Detected! >>>')
            for key, group in cluster_groups:
                print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                group = group[['netflows', 'TotDur', 'minDur', 'maxDur', 'tcp', 'udp', 'internal', 'incoming', 'outgoing', 'http', 'dns', 'dhcp', 'ssl', 'ssh', 'Totbytes', 'Totpackets', 'packetImbalance', 'byteImbalance','DayofWeek', 'isClient']]

                outputdf = pd.concat([outputdf, group], axis=0)
            return outputdf.sort_values(by=['netflows', 'TotDur', 'minDur', 'maxDur', 'tcp', 'udp', 'internal', 'incoming', 'outgoing', 'http', 'dns', 'dhcp', 'ssl', 'ssh', 'Totbytes', 'Totpackets', 'packetImbalance', 'byteImbalance'],ascending=False).reset_index().to_json()
        else:
            return ('empty dataset')


if __name__ =='__main__':
    ad = conn_anomalyDetect()
    print(ad.predict(pd.read_json('new_test.json')))
