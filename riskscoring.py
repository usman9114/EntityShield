import ipaddress
import numpy as np
import pandas as pd
from db.db_operations import db_ops
import json
import time
from apscheduler.schedulers.blocking import BlockingScheduler


class risk_scoring():

    def __init__(self):
        self.db = db_ops()
        self.data = self.db.fetch_malicious(1)
        self.private_ip_list = ['203.223.175.76',
                                '208.67.220.220', '80.80.81.81']

    def get_top_risk(self):
        try:
            df = self.db.fetch_risk_table()
            total_mean = df['total'].mean()
            total_std = df['total'].std()
            df = df.groupby(['ip', 'created_at']).sum().reset_index()
            high_risk_user = list(set(df[df['total'] > total_mean + total_std]['ip']))
            return high_risk_user
        except:
            return []


    def private_ip(self, src_ip, dest_ip):
        if ipaddress.ip_address(src_ip).is_private or src_ip in self.private_ip_list:
            return src_ip
        elif ipaddress.ip_address(dest_ip).is_private or dest_ip in self.private_ip_list:
            return dest_ip
        return np.nan

    def calc_score(self, df):
        def make_unique():
            return list(set([f for f in df['ip_src_addr'] if ipaddress.ip_address(f).is_private or f in self.private_ip_list] \
                            + [f for f in df['ip_dst_addr'] if ipaddress.ip_address(f).is_private or f in self.private_ip_list]))


        ip_lst = make_unique()

        temp_df_score = pd.DataFrame()

        for ip in ip_lst:
            temp = df.loc[(df['ip_src_addr'] == ip) | (df['ip_dst_addr'] == ip)]
            temp_score = temp.groupby(['ip_src_addr', 'ip_dst_addr']).sum().reset_index()
            temp_df_score = pd.concat([temp_score, temp_df_score], axis=0)

        temp_df_score['IP Address'] = temp_df_score.apply(lambda x: self.private_ip(x['ip_src_addr'], x['ip_dst_addr']),
                                                          axis=1)
        temp_df_score = temp_df_score[['IP Address', 'Bot_agent', 'DGA', 'conn_anomaly', 'uri_check', 'dns_anomaly', 'http_anomaly',
                                       'phishing_attack']]
        return temp_df_score


    def consolidate_sources(self, df_supervised_models, df_conn, df_an_http, df_dns,df_sysmon, df_appcheck):
        if df_supervised_models.shape[0] == 0:
            print('df attacks empty')
        elif df_conn.shape[0] == 0:
            print('df conn empty')
        elif df_an_http.shape[0] == 0:
            print('df http empty')
        elif df_dns.shape[0] == 0:
            print('df http empty')
        elif df_sysmon.shape[0] == 0:
            print('df sysmon')
        elif df_appcheck.shape[0] == 0:
            print('df appcheck')

        def preprocess_supervised_models(df, df_appcheck):
            df = df.copy().reset_index(drop=True)[['ip_src_addr', 'ip_dst_addr', 'phishing', 'bot_type', 'dga','uricheck']]
            df2 = pd.DataFrame()

            df2[['ip_src_addr', 'ip_dst_addr']]=df[['ip_src_addr', 'ip_dst_addr']]
            df2['phishing_attack'] = df['phishing'].apply(lambda x: False if x is None else json.loads(x)['Phishing'][0])*1
            df2['DGA'] = df['dga'].apply(lambda x: False if x is None else json.loads(x)['DGA'])*1
            df2['uri_check'] = df['uricheck'].apply(lambda x: False if x is None else json.loads(x)['is_malicious'][0])*1
            df2['Bot_agent'] = df['bot_type'].apply(lambda x: False if x is None else json.loads(x)['is_crawler'])*1
            del df
            df2 = df2[['ip_src_addr', 'ip_dst_addr', 'phishing_attack', 'DGA', 'Bot_agent', 'uri_check']]

            df2 = df2[df2[['phishing_attack', 'DGA', 'Bot_agent', 'uri_check']].values.sum(axis=1) != 0]  # 3X faster
            return df2.fillna(0)

        def preprocess_unsupervised(df_conn, df_http, df_dns):
            df_conn['conn_anomaly'] = 1
            df_dns['dns_anomaly'] = 1
            df_http['http_anomaly'] = 1
            df_conn_score = df_conn[['ip_src_addr', 'ip_dst_addr', 'conn_anomaly']]
            df_dns_score = df_dns[['ip_src_addr', 'ip_dst_addr', 'dns_anomaly']]
            df_http_score = df_http[['ip_src_addr', 'ip_dst_addr', 'http_anomaly']]
            # renaming df_conn cols to same names as others
            df_conn_score.columns = ['ip_src_addr', 'ip_dst_addr', 'conn_anomaly']
            final_score = pd.concat([df_conn_score, df_dns_score, df_http_score])
            return final_score

        result = pd.concat([preprocess_supervised_models(df_supervised_models,df_appcheck), preprocess_unsupervised(df_conn, df_an_http, df_dns)], sort=True)

        result = result[
            ['ip_src_addr', 'ip_dst_addr', 'Bot_agent', 'DGA', 'conn_anomaly', 'uri_check', 'dns_anomaly', 'http_anomaly',
             'phishing_attack']]

        result = result.fillna(0)
        return self.calc_score(result).groupby('IP Address').sum()



    def weigthed_scoring(self, df, **args):
        df = df.copy()
        df['Bot_agent'] = df['Bot_agent'] * args['Bot_agent']
        df['DGA'] = df['DGA'] * args['DGA']
        df['uri_check'] = df['uri_check'] * args['uri_check']
        df['conn_anomaly'] = df['conn_anomaly'] * args['conn_anomaly']
        df['dns_anomaly'] = df['dns_anomaly'] * args['dns_anomaly']
        df['http_anomaly'] = df['http_anomaly'] * args['http_anomaly']
        df['phishing_attack'] = df['phishing_attack'] * args['phishing_attack']
        return df

    def get_weighted_score(self, df):
        final_score = self.weigthed_scoring(df, Bot_agent=2, DGA=1, conn_anomaly=0.5, dns_anomaly=1.5,
                                     http_anomaly=0.5, phishing_attack=2, uri_check=2)
        final_score['total'] = final_score.sum(axis=1)
        final_score = final_score.sort_values(by='total', ascending=False)
        print(final_score)
        return final_score

if __name__ =='__main__':

    def calc_recent_risk():
        try:
            rs = risk_scoring()
        except Exception as e:
            print(e)
        print('Last risk score updated at {}'.format(
        pd.to_datetime(int(round(time.time() * 1000)), unit='ms')))

        df = rs.consolidate_sources(*rs.data)
        df = rs.get_weighted_score(df)
        df['malicious_processes'] = None
        df['new_apps'] = None
        df = df[['Bot_agent', 'DGA', 'phishing_attack', 'conn_anomaly', 'dns_anomaly',
                 'malicious_processes', 'new_apps', 'uri_check', 'http_anomaly', 'total']]
        rs.db.insert_score(df.reset_index())
        print('record inserted....')
        ip_lst = rs.get_top_risk()
        print('High Risk user'.format(ip_lst))
        rs.db.insert_high_score(ip_lst)
        rs.db.conn.close()

    calc_recent_risk()
    scheduler = BlockingScheduler()
    scheduler.add_job(calc_recent_risk, 'interval', hours=1)
    scheduler.start()
