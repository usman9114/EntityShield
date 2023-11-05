from elasticsearch import Elasticsearch,helpers
import pandas as pd
import time
import datetime
from scipy.ndimage import gaussian_filter
from config.ElasticSearch_config import read_elastic_config


class PcrModel:
    def __init__(self):

        self.hosts = [read_elastic_config()]

        self.elastic = Elasticsearch(hosts=self.hosts,timeout=30, max_retries=10, retry_on_timeout=True)
        print('Connected to Elastic Search @{}'.format(self.hosts))
        # self.profile_path = join('app_checker', 'profiles')

    def fetch_data(self, ip, duration):
        print(ip)
        hosts = [{'host': '172.16.4.23', 'port': 9200}]

        elastic = Elasticsearch(hosts=hosts, timeout=30, max_retries=10, retry_on_timeout=True)
        date = pd.to_datetime(int(round(time.time() * 1000)), unit='ms')
        past_date = date - datetime.timedelta(days=duration)
        body = {
            "_source": ['bro_timestamp',
                        'ip_src_addr', 'ip_dst_addr',
                        'orig_bytes',
                        'resp_bytes'],

            "query": {
                "bool": {
                    "must": [
                        {"range": {"bro_timestamp": {"gte": round(past_date.timestamp()), "lt": round(date.timestamp())}}},
                        {"match": {"protocol": "conn"}},

                        {
                            "bool": {
                                "should": [
                                    {"match": {"ip_src_addr": ip}},

                                    {"match": {"ip_dst_addr": ip}},

                                ]
                            }
                        }

                    ]

                }}}
        result = helpers.scan(elastic, query=body, index="bro*", preserve_order=True, raise_on_error=False, size=10000,
                              scroll='100m')
        df = pd.DataFrame.from_dict([document['_source'] for document in result])
        return df

    def get_pcr(self, ip, duration=7):
        df = self.fetch_data(ip=ip, duration=duration)
        df['bro_timestamp'] = pd.to_datetime(df['bro_timestamp'], unit='s')
        df.index = pd.to_datetime(df['bro_timestamp'], unit='s')
        df = df.groupby(pd.Grouper(level='bro_timestamp', freq='5T')).mean()
        df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce')
        df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce')
        df['pcr'] = (df['orig_bytes'] - df['resp_bytes']) / (df['orig_bytes'] + df['resp_bytes'])
        df['total'] = df['orig_bytes'] + df['resp_bytes']
        df['gussian_mean'] = gaussian_filter(df['pcr'], 5)
        df['total_smooth'] = gaussian_filter(df['total'], 5)
        df.index = pd.to_datetime(df.index, unit='s')
        df.dropna(inplace=True)

        df['outlier'] = 0
        df.loc[df['pcr'] > df['pcr'].mean() + df['pcr'].std() * 3, 'outlier'] = 1
        return df[['pcr', 'gussian_mean', 'total_smooth', 'outlier']].to_json()


if __name__ =='__main__':
    pcr = PcrModel()
    print(pcr.get_pcr(ip='172.16.4.79',duration=7))

















