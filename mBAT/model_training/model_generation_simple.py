"""Anomaly Detection Example"""
import numpy as np
import ipaddress

# Third Party Imports
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'

from sklearn.ensemble import IsolationForest
from zat import dataframe_to_matrix
from joblib import load, dump

chunk_size = 500000
path_to_mapping = 'assests_mapping/Copy of Updated Mac List(6048).xlsx'
path_to_profiles ='profiles'
path_to_generic_model_dir = 'model_training/network-model'
path_to_user_model_dir = 'model_training/user-model'

profiles_dict = {}
user_model_train_dict = {}
transformer = None
features =['netflows', 'TotDur', 'minDur', 'maxDur', 'tcp', 'udp', 'internal', 'incoming', 'outgoing', 'http',
            'dns', 'dhcp', 'ssl', 'ssh', 'Totbytes', 'Totpackets', 'packetImbalance', 'byteImbalance','DayofWeek', 'isClient']



def private_ip( src_ip, dest_ip):
    if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(
            src_ip).is_multicast or src_ip in d.keys():
        return src_ip
    elif ipaddress.ip_address(dest_ip).is_private or ipaddress.ip_address(
            dest_ip).is_multicast or dest_ip in d.keys():
        return dest_ip
    else:
        return np.nan

def client_server(src_ip, dest_ip):
    if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(src_ip).is_multicast or src_ip in d.keys():
        return 'client'
    elif ipaddress.ip_address(dest_ip).is_private or ipaddress.ip_address(
            dest_ip).is_multicast or dest_ip in d.keys():
        return 'server'
    else:
        return np.nan

def map_ip_list(path):
    ip_info = pd.concat(pd.read_excel(path, sheet_name=None).values())
    host_names = list(ip_info['Hostname'].values)
    ips = list(ip_info['IP address'].values)
    d = {k: v for k, v in zip(ips, host_names)}
    return d
d = map_ip_list(path_to_mapping) # dict

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return ip
    except:
        return np.nan

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

def preprocessing(bro_df):
    # print('1. Cleaning Services.....')
    bro_df = bro_df[bro_df['service'].isin(['http', 'dns', 'dhcp', 'ssl', 'ssh'])]
    bro_df.loc[:, 'orig_bytes'] = pd.to_numeric(bro_df.loc[:, 'orig_bytes'], errors='coerce')
    bro_df.loc[:, 'orig_bytes'] = bro_df.loc[:, 'orig_bytes'].fillna(0)

    # print('2. Cleaning/ Validating IP address.....')
    bro_df.loc[:, 'id.orig_h'] = bro_df.loc[:,'id.orig_h'].apply(lambda x: validate_ip(x))
    bro_df.loc[:, 'id.resp_h'] = bro_df.loc[:,'id.resp_h'].apply(lambda x: validate_ip(x))
    bro_df = bro_df[bro_df.loc[:,'id.orig_h'].notna() & bro_df.loc[:, 'id.resp_h'].notna()]

    # print('TS to Timestamp format')
    # bro_df.loc[:, 'ts'] = pd.to_datetime(bro_df['ts'])
    # print('2. Assinging Names to IP address.....')
    # bro_df['Hostname_orig'] = bro_df['id.orig_h'].apply(lambda x : d.get(x,np.nan))
    # bro_df['Hostname_resp'] = bro_df['id.resp_h'].apply(lambda x : d.get(x,np.nan))

    # print('3. Generating direction..........')
    bro_df.loc[:,'direction'] = bro_df.apply(lambda row: traffic_direction(row), axis=1)

    # print('5. Cleansing resp bytes')
    bro_df.loc[:, 'resp_bytes'] = pd.to_numeric(bro_df.loc[:,'resp_bytes'], errors='coerce')
    bro_df.loc[:, 'resp_bytes'] = bro_df.loc[:,'resp_bytes'].fillna(0)

    # print('6. Cleansing resp packets')
    bro_df.loc[:, 'resp_pkts'] = pd.to_numeric(bro_df['resp_pkts'], errors='coerce')
    bro_df.loc[:, 'resp_pkts'] = bro_df.loc[:,'resp_pkts'].fillna(0)

    # print('7. Cleansing orig_ip_bytes ')
    bro_df.loc[:, 'orig_ip_bytes'] = pd.to_numeric(bro_df.loc[:,'orig_ip_bytes'], errors='coerce')
    bro_df.loc[:, 'orig_ip_bytes'] = bro_df.loc[:,'orig_ip_bytes'].fillna(0)

    # print('8. Cleansing resp_ip_bytes ')
    bro_df.loc[:, 'resp_ip_bytes'] = pd.to_numeric(bro_df.loc[:,'resp_ip_bytes'], errors='coerce')
    bro_df.loc[:, 'resp_ip_bytes'] = bro_df.loc[:,'resp_ip_bytes'].fillna(0)

    # print('9. Cleansing id.resp_p')
    bro_df.loc[:, 'id.resp_p'] = pd.to_numeric(bro_df.loc[:,'id.resp_p'], errors='coerce')
    bro_df.loc[:, 'id.resp_p'] = bro_df['id.resp_p'].fillna(0)

    # print('10. Cleansing id.orig_p')
    bro_df.loc[:, 'id.orig_p'] = pd.to_numeric(bro_df.loc[:,'id.orig_p'], errors='coerce')
    bro_df.loc[:, 'id.orig_p'] = bro_df.loc[:,'id.orig_p'].fillna(0)

    # print('11. Converting Duration to Seconds')
    bro_df.loc[:, 'durationsec'] = pd.to_numeric(bro_df.duration, errors='coerce')
    bro_df.loc[:, 'durationsec'] = bro_df.loc[:, 'durationsec'].fillna(0)

    bro_df = bro_df[['ts', 'id.orig_h', 'id.resp_h', 'proto', 'id.resp_p', 'id.orig_p', 'durationsec',
                     'direction', 'service', 'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']]

    bro_df.columns = ['ts', 'SrcAddr', 'DstAddr', 'Proto', 'Dport', 'Sport', 'Dur', 'dir', 'service',
                      'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes', 'id.resp_p']  # or id.orig_p ? not sure
    return bro_df

def getFeatures(df):

    df = preprocessing(df)


    df.set_index(['SrcAddr', 'DstAddr', 'ts', 'id.resp_p'], inplace=True, drop=True)

    df[['Dport', 'Sport', 'Dur', 'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes']] = df[
        ['Dport', 'Sport', 'Dur', 'orig_pkts', 'resp_pkts', 'resp_bytes', 'orig_bytes']].apply(pd.to_numeric,
                                                                                               errors='coerce')
    group = df.groupby([pd.Grouper(level='SrcAddr'), pd.Grouper(level='DstAddr'), pd.Grouper(level='id.resp_p'),
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

    train_win['DayofWeek'] = [f[3].day_name() for f in train_win.index]
    train_win['privateIP'] = [private_ip(f[0], f[1]) for f in train_win.index]
    train_win['isClient'] = [client_server(f[0], f[1]) for f in train_win.index]
    train_win.fillna(0, inplace=True)
    return train_win.round(2)



def save_profiles(df_train):
    df_t = df_train.groupby('privateIP')
    for ip in pd.unique(df_train['privateIP']):
        try:
            dtemp = df_t.get_group(ip)
            profiles_dict[ip] = dtemp
            dtemp.to_csv('profiles/User-{}.csv'.format(ip))
            print(ip)
        except Exception as e:
            print(e)
    del df_t


def generic_model_train(df):
    # Use the zat DataframeToMatrix class
    to_matrix = dataframe_to_matrix.DataFrameToMatrix()
    train_matrix = to_matrix.fit_transform(df[features])
    print(train_matrix.shape)

    odd_clf = IsolationForest(contamination=0.0005, n_jobs=-1, verbose=0)  # Marking 10% as odd
    odd_clf.fit(train_matrix)
    print('dumping generic model to {}'.format(path_to_generic_model_dir))
    conn_pickle = {'model': odd_clf, 'tranformer': to_matrix}
    with open(path_to_generic_model_dir+'/generic_conn_v0.1.pkl', 'wb') as pickle_file:
        dump(conn_pickle, pickle_file)

def user_model_train():
    odd_clf = IsolationForest(contamination=0.005, n_jobs=-1, verbose=0)  # Marking 10% as odd
    for ip, df in profiles_dict.items():
        print(ip)
        transformer = load(path_to_generic_model_dir+'/generic_conn_v0.1.pkl')['tranformer']
        user_matrix = transformer.transform(df[features])

        odd_clf.fit(user_matrix)
        user_model_train_dict[ip] = odd_clf

    with open(path_to_user_model_dir+'/user_conn_v0.1.pkl', 'wb') as pickle_file:
        dump(user_model_train_dict, pickle_file)
    print('User-Model trained')

import warnings
warnings.filterwarnings('ignore')
def model_run():
    df_train = load('features-set/con_featureset_v1-1.pkl')
    df_train['netflows'] = pd.to_numeric(df_train['netflows'])
    print('training network model...')
    generic_model_train(df_train)
    save_profiles(df_train)
    print('training user model...')
    user_model_train()



