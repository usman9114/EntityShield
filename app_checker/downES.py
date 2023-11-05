from elasticsearch import Elasticsearch
from joblib import load
import pandas as pd
import json
import tldextract
from os.path  import join
from pandas.io.json import json_normalize
from config.ElasticSearch_config import read_elastic_config
import numpy as np
import time
import datetime


class topHost:
    def __init__(self):

        # self.hosts = [read_elastic_config()]
        self.hosts = [{'host': '172.16.4.56', 'port': 9200}]

        self.elastic = Elasticsearch(hosts=self.hosts,timeout=30, max_retries=10, retry_on_timeout=True)
        print('Connected to Elastic Search @{}'.format(self.hosts))
        # self.profile_path = join('app_checker', 'profiles')

def fetch_data(ip, duration=15):
    print(ip)
    hosts = [{'host': '172.16.4.23', 'port': 9200}]

    elastic = Elasticsearch(hosts=hosts, timeout=30, max_retries=10, retry_on_timeout=True)
    date = pd.to_datetime(int(round(time.time() * 1000)), unit='ms')
    past_date = date - datetime.timedelta(days=duration)
    body = {"query": {
        "bool": {
            "must": [
                {
                    "query_string": {
                        "query": "*",
                        "analyze_wildcard": 'true'
                    }
                },
                {"match": {"ip_src_addr":ip }},
                {"match": {"protocol": 'dns'}},

                {
                  "range": {
                    "bro_timestamp": {
                      "gte": round(past_date.timestamp()),
                      "lte": round(date.timestamp()),
                    }
                  }
                }
            ],
            "must_not": []
        }
    },
        "size": 0,
        "_source": {
            "excludes": []
        },
        "aggs": {
            "2": {
                "terms": {
                    "field": 'query',
                    "size": 10000,
                    "order": {
                        "_count": "desc"
                    }
                }
            }
        },


    }
    results = elastic.search(index='bro*', body=body)
    df = pd.DataFrame.from_dict(results['aggregations']['2']['buckets'])
    raw = df
    if df.empty:
        return {'Success': False, 'error': 'no data found in past {}'.format(duration)}

    if 'dns' =='dns':
        df['domain'] = df['key'].apply(lambda x: tldextract.extract(x).registered_domain)
        df['subdomain'] = df['key'].apply(lambda x: tldextract.extract(x).subdomain)
        df = df.groupby(['doc_count', 'domain'])['subdomain'].count().reset_index()[
            ['subdomain', 'doc_count', 'domain']]
        df.columns=['SubDomain', 'Visited', 'Domain']
        df = df.groupby('Domain')[['Visited', 'SubDomain']].sum().reset_index()
        df.sort_values(by='SubDomain', ascending=False, inplace=True)
        df = df.replace('', 0)
        df = df[df['Domain'] != 0]
        df=df.reset_index(drop=True)
        print(df.head())

        # [f for f in raw['key'] if df['Domain'][0] in f]
        return df

    elif 'dns' =='conn':
        return df.reset_index()


def run_profile_check(self, user):
    # profile_dic = load(join(self.profile_path, user+'.pkl'))
    input_df = self.fetch_data(user)


if __name__ =='__main__':
    import multiprocessing as mp
    ap = topHost()

    total = 0
    while True:
        try:
            ip = ['10.2.2.'+str(f) for f in range(1, 200)]
            # ip = ['10.2.2.195']
            print(ip)
            total +=len(ip)
            print(total)
            pool = mp.Pool(processes=13)
            res = pool.map(fetch_data, ip)
            res = [r for r in res if r is not None]
        except Exception as e:
            print(e)
            pass
    # print(ap.fetch_data(ip='10.2.2.195', proto='dns', field='query', duration=5))
















