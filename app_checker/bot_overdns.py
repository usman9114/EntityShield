from elasticsearch import Elasticsearch
import pandas as pd
import tldextract
from config.ElasticSearch_config import read_elastic_config
import time
import datetime

TIME_OUT = 30
MAX_RETRIES = 10


class TopHost:

    def __init__(self):

        self.hosts = [{'host': '172.16.4.23', 'port': 9200}]

        self.elastic = Elasticsearch(hosts=self.hosts, timeout=TIME_OUT, max_retries=MAX_RETRIES,
                                     retry_on_timeout=True)

        print('Connected to Elastic Search @{}'.format(self.hosts))

    def fetch_data(self, ip, proto, field, duration=1):
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
                    {"match": {"protocol": proto}},

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
                        "field": field,
                        "size": 10000,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            },


        }
        results = self.elastic.search(index='bro*', body=body)
        df = pd.DataFrame.from_dict(results['aggregations']['2']['buckets'])
        # raw = df
        if df.empty:
            return {'Success': False, 'error': 'no data found in past {} days'.format(duration)}

        if proto =='dns':
            df['domain'] = df['key'].apply(lambda x: tldextract.extract(x).registered_domain)
            df['subdomain'] = df['key'].apply(lambda x: tldextract.extract(x).subdomain)
            df = df.groupby(['doc_count', 'domain'])['subdomain'].count().reset_index()[
                ['subdomain', 'doc_count', 'domain']]
            df.columns=['SubDomain', 'Visited', 'Domain']
            df = df.groupby('Domain')[['Visited', 'SubDomain']].sum().reset_index()
            df.sort_values(by='SubDomain', ascending=False, inplace=True)
            df = df.replace('', 0)
            df = df[df['Domain'] != 0]
            df = df.reset_index(drop=True)

            # [f for f in raw['key'] if df['Domain'][0] in f]
            return {'Success': True, 'data': df.to_json()}

        elif proto =='conn':
            return df.reset_index()


if __name__ =='__main__':
    import multiprocessing as mp
    ap = TopHost()
    print(ap.fetch_data(ip='10.2.2.195', proto='dns', field='query', duration=7))
















