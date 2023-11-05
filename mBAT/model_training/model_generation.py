"""Anomaly Detection Example"""

import os
import sys
import argparse
import math
import numpy as np

from collections import Counter
import ipaddress
import time

# Third Party Imports
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'

from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from zat import log_to_dataframe
from zat import dataframe_to_matrix
from joblib import load,dump
import swifter
# Local imports

class userProfiling():

    def __init__(self):
        self.chunk_size = 500000 # depending on ram size
        self.path_to_mapping = '../Copy of Updated Mac List(6048).xlsx'
        self.path_to_profiles ='profiles'
        self.path_to_dataset = '../conn.csv'
        self.path_to_generic_model_dir = 'network-model'
        self.path_to_user_model_dir = 'user-model'

        self.d = self.map_ip_list(self.path_to_mapping) # dict
        self.profiles_dict = {}
        self.user_model_train_dict = {}
        self.transformer = None
        self.features =['netflows', 'TotDur', 'minDur', 'maxDur', 'tcp', 'udp', 'internal', 'incoming', 'outgoing', 'http',
                    'dns', 'dhcp', 'ssl', 'ssh', 'Totbytes', 'Totpackets', 'packetImbalance', 'byteImbalance']


    def private_ip(self, src_ip, dest_ip):
        if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(
                src_ip).is_multicast or src_ip in self.d.keys():
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

    def map_ip_list(self, path):
        ip_info = pd.concat(pd.read_excel(path, sheet_name=None).values())
        host_names = list(ip_info['Hostname'].values)
        ips = list(ip_info['IP address'].values)
        d = {k: v for k, v in zip(ips, host_names)}
        return d

    def validate_ip(self, ip):
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

    def preprocessing(self, bro_df):
        # print('1. Cleaning Services.....')
        bro_df = bro_df[bro_df['service'].isin(['http', 'dns', 'dhcp', 'ssl', 'ssh'])]
        bro_df['orig_bytes'] = pd.to_numeric(bro_df['orig_bytes'], errors='coerce')
        bro_df['orig_bytes'] = bro_df['orig_bytes'].fillna(0)

        # print('2. Cleaning/ Validating IP address.....')
        bro_df['id.orig_h'] = bro_df['id.orig_h'].apply(lambda x: self.validate_ip(x))
        bro_df['id.resp_h'] = bro_df['id.resp_h'].apply(lambda x: self.validate_ip(x))
        bro_df = bro_df[bro_df['id.orig_h'].notna() & bro_df['id.resp_h'].notna()]

        # print('TS to Timestamp format')
        bro_df['ts'] = pd.to_datetime(bro_df['ts'])
        # print('2. Assinging Names to IP address.....')
        # bro_df['Hostname_orig'] = bro_df['id.orig_h'].apply(lambda x : d.get(x,np.nan))
        # bro_df['Hostname_resp'] = bro_df['id.resp_h'].apply(lambda x : d.get(x,np.nan))

        # print('3. Generating direction..........')
        bro_df['direction'] = bro_df.apply(lambda row: self.traffic_direction(row), axis=1)

        # print('5. Cleansing resp bytes')
        bro_df['resp_bytes'] = pd.to_numeric(bro_df['resp_bytes'], errors='coerce')
        bro_df['resp_bytes'] = bro_df['resp_bytes'].fillna(0)

        # print('6. Cleansing resp packets')
        bro_df['resp_pkts'] = pd.to_numeric(bro_df['resp_pkts'], errors='coerce')
        bro_df['resp_pkts'] = bro_df['resp_pkts'].fillna(0)

        # print('7. Cleansing orig_ip_bytes ')
        bro_df['orig_ip_bytes'] = pd.to_numeric(bro_df['orig_ip_bytes'], errors='coerce')
        bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].fillna(0)

        # print('8. Cleansing resp_ip_bytes ')
        bro_df['resp_ip_bytes'] = pd.to_numeric(bro_df['resp_ip_bytes'], errors='coerce')
        bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].fillna(0)

        # print('9. Cleansing id.resp_p')
        bro_df['id.resp_p'] = pd.to_numeric(bro_df['id.resp_p'], errors='coerce')
        bro_df['id.resp_p'] = bro_df['id.resp_p'].fillna(0)

        # print('10. Cleansing id.orig_p')
        bro_df['id.orig_p'] = pd.to_numeric(bro_df['id.orig_p'], errors='coerce')
        bro_df['id.orig_p'] = bro_df['id.orig_p'].fillna(0)

        # print('11. Converting Duration to Seconds')
        bro_df['durationsec'] = pd.to_numeric(bro_df.duration, errors='coerce')
        bro_df['durationsec'] = bro_df['durationsec'].fillna(0)

        bro_df = bro_df[['ts', 'id.orig_h', 'uid', 'id.resp_h', 'proto', 'id.resp_p', 'id.orig_p', 'durationsec',
                         'direction', 'service', 'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']]

        bro_df.columns = ['ts', 'SrcAddr', 'session_id', 'DstAddr', 'Proto', 'Dport', 'Sport', 'Dur', 'dir', 'service',
                          'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']  # or id.orig_p ? not sure
        return bro_df

    def getFeatures(self, df):

        df = self.preprocessing(df)
        df.set_index(['SrcAddr', 'DstAddr', 'ts', 'Sport'], inplace=True, drop=True)

        group = df.groupby([pd.Grouper(level='SrcAddr'), pd.Grouper(level='DstAddr'), pd.Grouper(level='Sport'),
                            pd.Grouper(level='ts', freq='10T')]) # 10 min grouped

        # df_win.groupby(['SrcAddr'])
        #train_win = group.Dport.nunique()
        train_win = pd.DataFrame()
        # train_win['udest_ip'] = group.DstAddr.nunique()
        # train_win['udest_port'] = group.Dport.nunique()

        train_win['netflows'] = group.Dport.count()
        # train_win['uproto'] = group.Proto.nunique()
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
        train_win.fillna(0, inplace=True)
        return train_win.round(2)

    def execute_parallel(self):
        start_time = time.time()

        from joblib import delayed, Parallel

        df_train = pd.DataFrame()
        bro_conn_df = pd.read_csv(self.path_to_dataset, chunksize=self.chunk_size)

        for i, chunk in enumerate(bro_conn_df):
            print('processing chunk ' + str(i))
            print('chunk size to be processed'.format(chunk.shape))
            splits = np.split(chunk.iloc[chunk.shape[0] % 8:, :], 8)
            print('skiping...{}'.format(chunk.shape[0] % 8))
            list_df = Parallel(n_jobs=-1)(delayed(self.getFeatures)(i) for i in splits)
            df_train_temp = pd.concat(list_df, axis=0)
            df_train = pd.concat([df_train_temp, df_train])

        print("--- %s seconds ---" % (time.time() - start_time))

        return df_train

    def save_profiles(self, df_train):
        df_t = df_train.groupby('privateIP')
        for ip in pd.unique(df_train['privateIP']):
            try:
                dtemp = df_t.get_group(ip)
                self.profiles_dict[ip] = dtemp
                dtemp.to_csv('profiles/User-{}.csv'.format(ip))
                print(ip)
            except Exception as e:
                print(e)
        del df_t


    def generic_model_train(self, df):
        # Use the zat DataframeToMatrix class
        to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        train_matrix = to_matrix.fit_transform(df[self.features])
        self.transformer = to_matrix
        print(train_matrix.shape)

        odd_clf = IsolationForest(behaviour='new', contamination=0.005, n_jobs=-1, verbose=0)  # Marking 10% as odd
        odd_clf.fit(train_matrix)
        print('dumping generic model to {}'.format(self.path_to_generic_model_dir))
        conn_pickle = {'model': odd_clf, 'tranformer': to_matrix}
        with open(self.path_to_generic_model_dir+'/generic_conn_v0.1.pkl', 'wb') as pickle_file:
            dump(conn_pickle, pickle_file)

    def user_model_train(self):
        odd_clf = IsolationForest(behaviour='new', contamination=0.0005, n_jobs=-1, verbose=0)  # Marking 10% as odd
        for ip, df in self.profiles_dict.items():
            print(ip)
            if self.transformer != None:
                user_matrix = self.transformer.transform(df[self.features])
            else:
                self.transformer = load(self.path_to_generic_model_dir+'/generic_conn_v0.1.pkl')['tranformer']
                user_matrix = self.transformer.transform(df[self.features])

            odd_clf.fit(user_matrix)
            self.user_model_train_dict[ip] = odd_clf

        with open(self.path_to_user_model_dir+'/user_conn_v0.1.pkl', 'wb') as pickle_file:
            dump(self.user_model_train_dict, pickle_file)
        print('User-Model trained')

if __name__ =='__main__':
    import warnings
    warnings.filterwarnings('ignore')
    up = userProfiling()
    df_train = up.execute_parallel()

    no_index_df = df_train.reset_index()
    df_train['DayofWeek'] = no_index_df['ts'].dt.day_name().values
    df_train['privateIP'] = no_index_df.swifter.apply(lambda x: up.private_ip(x['SrcAddr'], x['DstAddr']), axis=1).values
    df_train['isClient'] = no_index_df.swifter.apply(lambda x: up.client_server(x['SrcAddr'], x['DstAddr']), axis=1).values
    dump(df_train, 'features-set/con_featureset_v1.pkl')
    del no_index_df
    print('training network model...')
    up.generic_model_train(df_train)
    up.save_profiles(df_train)
    print('training user model...')
    up.user_model_train()




