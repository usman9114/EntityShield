from elasticsearch import Elasticsearch
from joblib import load
import pandas as pd
import json
from os.path import join
from os.path  import join
from pandas.io.json import json_normalize
import elasticsearch.helpers
from config.ElasticSearch_config import read_elastic_config
import numpy as np
import time


class AppTest:
    def __init__(self):

        self.hosts = [read_elastic_config()]
        self.elastic = Elasticsearch(hosts=self.hosts)
        print('Connected to Elastic Search @{}'.format(self.hosts))
        self.profile_path = join('app_checker', 'profiles')

    def fetch_data(self, user, duration):

        date = pd.to_datetime(int(round(time.time() * 1000)), unit='ms').tz_localize('UTC').tz_convert('Asia/Karachi')
        current = str(date).replace(' ', 'T').split('.')[0]
        past_date = date - pd.Timedelta(days=duration)
        past_date = str(past_date).replace(' ', 'T').split('.')[0]

        body = {"_source": ['@timestamp', 'computer_name', 'event_id', 'task'], "query": {
            "bool": {
                "filter": [
                    {
                        "terms": {
                            'event_id': ['4624', '4634']
                        }
                    },
                    {
                        "term": {
                            "computer_name": {"value": str(user)}
                        }
                    },
                    {"range": {"@timestamp": {"gte": past_date, "lt": current}}},

                ]
            }
        }}
        result = elasticsearch.helpers.scan(self.elastic, query=body, index="winlogbeat*", preserve_order=True,
                                         raise_on_error=False, size=1000, scroll='100m', request_timeout=100)

        df = pd.DataFrame.from_dict([document['_source'] for document in result])
        return df

    def process_data(self, user, duration):

        df = self.fetch_data(user, duration)
        df['@timestamp'] = pd.to_datetime(df['@timestamp'])
        df.sort_values(by='@timestamp', inplace=True)
        def remove_dup(grp):
            return grp.drop_duplicates(subset='task')

        df = df.groupby(pd.Grouper(key='@timestamp', freq='10min')).apply(remove_dup).reset_index(level=1, drop=True)
        df['Duration'] = [time.mktime(t.timetuple()) / 60.0 for t in df['@timestamp']]
        df['hour'] = df['@timestamp'].dt.hour
        df['duration_diff'] = df['Duration'].diff()
        df['outOfHours'] = (~df['hour'].isin(range(8, 19))) & (df['task'] == 'Logon')
        df['large_duration'] = df['duration_diff'] > df['duration_diff'].mean() + 6 * df['duration_diff'].std()

        return df.to_json()


if __name__ =='__main__':
    ap = AppTest()
    print(ap.run_profile_check('Mahmood-PC-TAP',50))
















