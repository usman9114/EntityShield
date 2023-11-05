from elasticsearch import Elasticsearch
from joblib import load
import pandas as pd
import json
from os.path import join
from os.path  import join
from pandas.io.json import json_normalize
from config.ElasticSearch_config import read_elastic_config
import numpy as np


class AppTest:
    def __init__(self):

        self.hosts = [read_elastic_config()]
        self.elastic = Elasticsearch(hosts=self.hosts)
        print('Connected to Elastic Search @{}'.format(self.hosts))
        self.profile_path = join('app_checker', 'profiles')

    def fetch_data(self,user):
        body = {"query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "*",
                            "analyze_wildcard": 'true'
                        }
                    },
                    {"match": {"computer_name": user}},
                    {"match": {"source_name": "Microsoft-Windows-Sysmon"}},

                    #         {
                    #           "range": {
                    #             "@timestamp": {
                    #               "gte": 1597481759562,
                    #               "lte": 1613379359562,
                    #               "format": "epoch_millis"
                    #             }
                    #           }
                    #         }
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
        results = self.elastic.search(index='winlogbeat*', body=body)
        df = pd.DataFrame.from_dict(results['aggregations']['2']['buckets'])
        json_struct = json.loads(df.to_json(orient="records"))
        flat = json_normalize(json_struct)
        computer_name = flat['3.buckets'].apply(lambda x: x[0]['key'])
        flat['computer_name'] = computer_name
        flat['username'] = flat['computer_name'].apply(lambda x: x.split('\\')[1])
        flat['computer_name'] = flat['computer_name'].apply(lambda x: x.split('\\')[0])
        return flat
    def run_profile_check(self, user):
        profile_dic = load(join(self.profile_path, user+'.pkl'))
        input_df = self.fetch_data(user)
        max_of_app = max(profile_dic.values())
        input_df['label'] = input_df['key'].map(profile_dic).fillna(max_of_app+100)
        new_app_list = [f.strip() for f in input_df['key'].iloc[np.where(input_df['label'] > max_of_app)]]
        input_df['new_app'] = input_df['key'].isin(new_app_list) * 1
        input_df=input_df[['computer_name','doc_count', 'username', 'key', 'label', 'new_app']]
        return input_df.to_json()


if __name__ =='__main__':
    ap = AppTest()
    print(ap.run_profile_check('UsmanQureshi'))
















