from elasticsearch import Elasticsearch
from joblib import dump
import numpy as np
from sklearn.preprocessing import LabelEncoder
from pandas.io.json import json_normalize
import pandas as pd
from config.ElasticSearch_config import read_elastic_config
import json


class profileBuilder:


    def __init__(self):

        self.hosts = [read_elastic_config()]
        self.elastic = Elasticsearch(hosts=self.hosts)
        self.flat = pd.DataFrame()
        self.body = {"query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "*",
                            "analyze_wildcard": 'true'
                        }
                    },
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
                        "field": "event_data.Product",
                        "size": 10000,
                        "order": {
                            "_count": "desc"
                        }
                    },
                    "aggs": {
                        "3": {
                            "terms": {
                                "field": "event_data.User",
                                "size": 10000,
                                "order": {
                                    "_count": "desc"
                                }
                            }
                        }
                    }
                }
            }
        }

    def build_profile(self):
        df = self.fetch_data()
        for computer_name in df['computer_name'].unique():
            print(computer_name)
            temp_profile = df[df['computer_name'] == computer_name]
            product_le = LabelEncoder().fit(list(temp_profile['key'].unique()))
            product_dic = dict(zip(product_le.classes_, product_le.transform(product_le.classes_)))
            dump(product_dic, filename='app_checker/profiles/' + computer_name + '.pkl')
        return [f for f in df['computer_name'].unique()]


    def fetch_data(self):
        results = self.elastic.search(index='winlogbeat*', body=self.body)
        df = pd.DataFrame.from_dict(results['aggregations']['2']['buckets'])
        json_struct = json.loads(df.to_json(orient="records"))
        flat = json_normalize(json_struct)
        computer_name = flat['3.buckets'].apply(lambda x: x[0]['key'])
        flat['computer_name'] = computer_name
        flat['username'] = flat['computer_name'].apply(lambda x: x.split('\\')[1])
        flat['computer_name'] = flat['computer_name'].apply(lambda x: x.split('\\')[0])
        return flat[['key', 'computer_name', 'doc_count']]

if __name__ =='__main__':
    profiler = profileBuilder()
    profiler.fetch_data()
    profiler.build_profile(profiler.flat)

















