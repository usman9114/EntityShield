import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from datetime import datetime
import numpy as np
import re
from tensorflow.keras.models import load_model
import joblib
from config.ElasticSearch_config import read_elastic_config
from elasticsearch import Elasticsearch
import elasticsearch.helpers
import time
import json

class sysmon_rnn:
    def __init__(self):
        self.MAX_TIMESTEPS = 128
        self.binary_le = joblib.load('win_activity/binary_le.pkl')
        self.path_le = joblib.load('win_activity/path_le.pkl')
        self.N = 7
        self.model = load_model('win_activity/newLstm')
        self.hosts = [read_elastic_config()]
        self.elastic = Elasticsearch(hosts=self.hosts)

    def fetch_data(self, user, duration_in_days=30):

        date = pd.to_datetime(int(round(time.time() * 1000)), unit='ms').tz_localize('UTC').tz_convert('Asia/Karachi')
        current = str(date).replace(' ', 'T').split('.')[0]
        past_date = date - pd.Timedelta(days=duration_in_days)
        past_date = str(past_date).replace(' ', 'T').split('.')[0]

        body = {
            "_source": ['event_id', 'computer_name', 'event_data.UtcTime', 'event_data.ProcessId', 'event_data.Image',
                        'event_data.ImageLoaded', 'event_data.CommandLine', 'event_data.ParentImage',
                        'event_data.ParentCommandLine',
                        'event_data.DestinationPort', 'event_data.Protocol', 'event_data.QueryName',
                        'event_data.DestinationIp', 'event_data.DestinationHostname'],

            "query": {
                "bool": {
                    "must": [
                        {"match": {"computer_name": user}},
                        {"match": {"source_name": "Microsoft-Windows-Sysmon"}},
                        {"range": {"@timestamp": {"gte": past_date, "lt": current}}},
                    ]

                }}}
        result = elasticsearch.helpers.scan(self.elastic, query=body, index="winlogbeat*", preserve_order=True,
                                            raise_on_error=False, size=1000, scroll='1m')
        df = pd.DataFrame.from_dict([document['_source'] for document in result])
        json_struct = json.loads(df.to_json(orient="records"))
        del df
        from pandas.io.json import json_normalize
        flat = json_normalize(json_struct)
        return flat

    def preprocess_df(self, df):
        prefix = 'event_data.'
        for f in ['UtcTime', 'ProcessId', 'Image', 'ImageLoaded', 'CommandLine', 'ParentImage', 'ParentCommandLine',
                  'DestinationPort', 'Protocol', 'DestinationIp', 'DestinationHostname']:
            df.rename(columns={prefix + f: f}, inplace=True)
        df.rename(columns={'event_id': 'EventID'}, inplace=True)

        fields = ['UtcTime', 'ProcessId', 'EventID', 'computer_name', 'Image', 'CommandLine', 'ParentImage',
                  'ParentCommandLine', 'DestinationPort', 'Protocol', 'DestinationIp',
                  'DestinationHostname']

        newdf = df[fields]
        newdf = newdf.replace(pd.np.nan, '')

        # drop all records where ProcessId in NaN (happens for WMI events, cannot classify [TODO: think how to overcome and add to dataset])
        newdf = newdf[~newdf.ProcessId.isna()]

        # drop EventID 5 - ProcessTerminated as not valuable
        newdf.drop(newdf[newdf.EventID == '5'].index, inplace=True)

        # get binary name (last part of "Image" after "\")
        newdf['binary'] = newdf.Image.str.split(r'\\').apply(lambda x: x[-1].lower())

        # same with binary pathes
        newdf['path'] = newdf.Image.str.split(r'\\').apply(lambda x: '\\'.join(x[:-1]).lower())

        newdf['arguments'] = newdf.CommandLine.fillna('empty').str.split(). \
            apply(lambda x: ' '.join(x[1:]))

        # add new features whether suspicious string are in arguments?
        # 1. base64?
        # will match at least 32 character long consequent string with base64 characters only
        b64_regex = r"[a-zA-Z0-9+\/]{64,}={0,2}"

        # map this search as 0 and 1 using astype(int)
        b64s = newdf['arguments'].apply(lambda x: re.search(b64_regex, x)).notnull()
        newdf['b64'] = b64s.astype(int)

        # matches if there's call for some file with extension (at the end dot) via UNC path
        unc_regex = r"\\\\[a-zA-Z0-9]+\\[a-zA-Z0-9\\]+\."
        uncs = newdf['arguments'].apply(lambda x: re.search(unc_regex, x)).notnull()

        url_regex = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
        urls = newdf['arguments'].apply(lambda x: re.search(url_regex, x)).notnull()

        # verified pd.concat part - merges two boolean series correctly
        newdf['unc_url'] = pd.concat([uncs, urls]).reset_index(drop=True).astype(int)
        newdf['network'] = newdf['Protocol'].notnull().astype(int)

        #     newdf = newdf[['ProcessId','binary','EventID','path', 'unc_url', 'b64', 'network']]
        # treat eventID as int8
        newdf['EventID'] = newdf['EventID'].astype('int8')
        newdf = newdf.replace('', pd.np.nan)

        return newdf.reset_index()

    def groupby_transform(self, dataframe, column):
        dataframe = dataframe[['index', 'ProcessId', 'binary', 'EventID', 'path', 'unc_url', 'b64', 'network']].dropna()
        total = len(dataframe.groupby(column))
        start = datetime.now()
        print(f"Started at: {start}")

        print(f"Total categories of '{column}': '{total}'")
        print(f"Unique values: {dataframe[column].nunique()}")

        # Initialize Numpy Arrays with correct shape
        processed = np.empty(shape=(0, self.MAX_TIMESTEPS, self.N)).astype(np.int16)

        binary_dic = dict(zip(self.binary_le.classes_, self.binary_le.transform(self.binary_le.classes_)))
        path_dic = dict(zip(self.path_le.classes_, self.path_le.transform(self.path_le.classes_)))

        try:
            for i, (value, df) in enumerate(dataframe.groupby(column)):
                # skip processes with less than 3 events
                # - too little to identify malicious activity
                if len(df) < 4:
                    continue

                # Create 3D array from
                temp_X = np.hstack((
                    df[['EventID', 'unc_url', 'b64', 'network']].to_numpy(),
                    df['binary'].map(binary_dic).fillna(0).astype(int).values.reshape(-1, 1),
                    df['path'].map(path_dic).fillna(0).astype(int).values.reshape(-1, 1),
                    df['index'].values.reshape(-1, 1)
                ))

                # PADDING
                temp_X = pad_sequences(temp_X.T, maxlen=self.MAX_TIMESTEPS).T
                # adding this example to actual set
                processed = np.concatenate((processed, temp_X.reshape(1, self.MAX_TIMESTEPS, self.N)))

            end = datetime.now()
            print(f"Ended at: {end}")
            print(f"Script completion time: {end - start}")
            return processed
        except Exception as e:
            print(e)

    def inverse_transform(self, input_key, dic):
        return ''.join([key for key, value in dic.items() if value == input_key])

    def predict(self, user, duration):
        df = self.fetch_data(user=user, duration_in_days=duration)
        if df.empty:
            return {'Success': False, 'error': 'No data of {} is available for past {} days'.format(user, duration)}
        new_df = self.preprocess_df(df)
        processed = self.groupby_transform(new_df, 'ProcessId')
        try:
            result = pd.concat(
                [pd.DataFrame(f, columns=['EventID', 'unc_url', 'b64', 'network', 'Binary', 'Path', 'index']) for f in
                 processed[np.where(self.model.predict_classes(processed[:, :, :6]).reshape(1, -1)[0] == 1)[0]]])

        except:
            return {'Success': False, 'error': 'no malicious activity found'}

        finally:
            out_put = pd.merge(result[['index']],
                               new_df[['UtcTime', 'computer_name', 'Image', 'index', 'ProcessId', 'arguments',
                                       'CommandLine', 'ParentImage', 'ParentCommandLine', 'DestinationPort', 'b64',
                                       'path', 'network', 'EventID', 'binary', 'unc_url',
                                       'Protocol', 'DestinationIp', 'DestinationHostname']], on='index', how='inner')
            print('out put')
            out_put= out_put[['UtcTime', 'computer_name', 'ProcessId', 'EventID', 'unc_url', 'b64', 'network', 'binary', 'path',
                     'Image', 'arguments', 'CommandLine',
                     'ParentImage', 'ParentCommandLine', 'DestinationPort', 'Protocol', 'DestinationIp',
                     'DestinationHostname']].to_json()
            return {'Success': True, 'data': out_put}



if __name__ == '__main__':
    sysm = sysmon_rnn()
    # df = pd.read_json('test6.json')
    #
    # # df = df[df['source_name']=='Microsoft-Windows-Sysmon']
    # # prefix = 'event_data.'
    # # for f in ['UtcTime', 'ProcessId', 'Image', 'ImageLoaded', 'CommandLine', 'ParentImage', 'ParentCommandLine',
    # #           'DestinationPort', 'Protocol', 'QueryName']:
    # #     df.rename(columns={prefix + f: f}, inplace=True)
    # # df.rename(columns={'event_id': 'EventID'}, inplace=True)
    # fields = ['UtcTime', 'ProcessId', 'EventID', 'computer_name', 'Image', 'CommandLine', 'ParentImage',
    #           'ParentCommandLine',
    #           'DestinationPort', 'Protocol', 'QueryName']
    # #     fields = [prefix+'UtcTime', prefix+'ProcessId', 'event_id', 'user', prefix+'Image', prefix+'ImageLoaded', prefix+'CommandLine',prefix+'ParentImage', prefix+'ParentCommandLine', prefix+'DestinationPort', prefix+'Protocol', prefix+'QueryName']
    #
    # # newdf = df[fields]
    # # newdf.to_json('winlog_test.json')
    print(sysm.predict('UsmanQureshi'))
