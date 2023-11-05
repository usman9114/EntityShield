import pandas as pd
from subprocess import call
from pyod.models.pca import PCA
import numpy as np
from joblib import Parallel, delayed
import warnings
import swifter
import ipaddress
import os
import gzip


class LongConn:
    def __init__(self):
        self.ano_amount = 100
        self.mode = 'zeek'
        self.conn_file = 'conn.{}:00:00-{}:00:00.log.gz'
        self.from_hour = None
        self.to_hour = None
        self.CONN_LOG = os.path.join('Anomaly_detection', 'real_fast_longConn', 'data', self.conn_file)

    def set_mode(self, mode='zeek'):
        self.mode = mode


    # This horrible hack is only to stop sklearn from printing those warnings
    def warn(*args, **kwargs):
        pass


    warnings.warn = warn

    def traffic_direction(self, conn_row):
        """Determine the direction of the connection traffic (takes a conn.log row)"""

        # First try to use the local orig/resp fields

        local_orig = ipaddress.ip_address(conn_row['id.orig_h']).is_private
        local_resp = ipaddress.ip_address(conn_row['id.resp_h']).is_private

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

    def getFeatures(self, bro_df):

        bro_df['ts'] = pd.to_datetime(bro_df['ts'], unit='s')
        bro_df['orig_bytes'].replace('-', '0', inplace=True)
        bro_df['orig_bytes'] = bro_df['orig_bytes'].fillna(0).astype('int64')
        bro_df['resp_bytes'].replace('-', '0', inplace=True)
        bro_df['resp_bytes'] = bro_df['resp_bytes'].fillna(0).astype('int64')
        bro_df['resp_pkts'].replace('-', '0', inplace=True)
        bro_df['resp_pkts'] = bro_df['resp_pkts'].fillna(0).astype('int64')
        bro_df['orig_ip_bytes'].replace('-', '0', inplace=True)
        bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].fillna(0).astype('int64')
        bro_df['resp_ip_bytes'].replace('-', '0', inplace=True)
        bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].fillna(0).astype('int64')
        bro_df['duration'].replace('-', '0', inplace=True)
        bro_df['duration'] = bro_df['duration'].fillna(0).astype('float64')
        return bro_df

    def detect(self, file=None, amountanom=100):
        """
        Function to apply a very simple anomaly detector
        amountanom: The top number of anomalies we want to print
        realtime: If we want to read the conn.log file in real time (not working)
        """

        # Create a Pandas dataframe from the conn.log
        with gzip.open(self.CONN_LOG.format(self.from_hour, self.to_hour)) as f:
            bro_df = pd.read_csv(f, sep="\t", comment='#',
                                 names=['ts',  'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h',
                                        'id.resp_p', 'proto', 'service', 'duration',  'orig_bytes',
                                        'resp_bytes', 'conn_state', 'local_orig', 'local_resp',
                                        'missed_bytes',  'history', 'orig_pkts', 'orig_ip_bytes',
                                        'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'])

        # In case you need a label, due to some models being able to work in a
        # semisupervized mode, then put it here. For now everything is
        # 'normal', but we are not using this for detection
        splits = np.array_split(bro_df, 7)  # np.split(chunk.iloc[chunk.shape[0] % 8:, :], 8)
        print('done')
        list_df = Parallel(n_jobs=-1, max_nbytes='50M', verbose=10)(delayed(self.getFeatures)(i) for i in splits)
        bro_df = pd.concat([pd.concat(list_df, axis=0)])

        # Replace the rows without data (with '-') with 0.
        # Even though this may add a bias in the algorithms,
        # is better than not using the lines.
        # Also fill the no values with 0
        # Finally put a type to each column



        # Save dataframe to disk as CSV
        # if dumptocsv != "None":
        #     bro_df.to_csv(dumptocsv)

        # Add the columns from the log file that we know are numbers. This is only for conn.log files.
        X_train = bro_df[['duration', 'orig_bytes', 'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']]
        # The X_test is where we are going to search for anomalies. In our case, its the same set of data than X_train.
        X_test = X_train
        # PCA. Good and fast!
        clf = PCA()
        X_train = X_train.values

        # Fit the model to the train data
        clf.fit(X_train)

        # get the prediction on the test data
        y_test_pred = clf.predict(X_test)  # outlier labels (0 or 1)

        y_test_scores = clf.decision_function(X_test)  # outlier scores

        # Convert the ndarrays of scores and predictions to  pandas series
        scores_series = pd.Series(y_test_scores)
        pred_series = pd.Series(y_test_pred)

        # Now use the series to add a new column to the X test
        X_test['score'] = scores_series.values
        X_test['pred'] = pred_series.values

        # Add the score to the bro_df also. So we can show it at the end
        bro_df['score'] = X_test['score']

        # Keep the positive predictions only. That is, keep only what we predict is an anomaly.
        X_test_predicted = X_test[X_test.pred == 1]

        # Keep the top X amount of anomalies
        top10 = X_test_predicted.sort_values(by='score', ascending=False).iloc[:amountanom]

        # Print the results
        # Find the predicted anomalies in the original bro dataframe, where the rest of the data is
        df_to_print = bro_df.iloc[top10.index]
        print('\nFlows of the top anomalies')

        # Only print some columns, not all, so its easier to read.
        df_to_print.loc[:, 'direction'] = df_to_print.swifter.apply(lambda row: self.traffic_direction(row), axis=1)
        df_to_print = df_to_print[df_to_print['direction'] != 'internal']
        df_to_print['duration'] = pd.to_timedelta(df_to_print['duration'], unit='s')

        df_to_print = df_to_print.drop(['history', 'local_orig', 'local_resp', 'missed_bytes', 'tunnel_parents'], axis=1)

        private_ips = [f for f in set(df_to_print['id.orig_h']) - set(df_to_print['id.resp_h']) if
                       ipaddress.ip_address(f).is_private]
        history_df = bro_df[(bro_df['id.orig_h'].isin(private_ips)) | (bro_df['id.resp_h'].isin(private_ips))]
        history_df['predicted'] = X_test.pred
        return {'Success': True, 'data': {'anomalies': df_to_print.to_json(), 'history': history_df.to_json()}}

    def get_data_from_sensor(self):
        current_ts = pd.Timestamp("today").strftime("%Y-%m-%d/%H")
        dir_name = current_ts.split('/')[0]
        self.from_hour = str(int(current_ts.split('/')[1]) - 1)
        self.to_hour = current_ts.split('/')[1]
        self.conn_file = self.conn_file.format(self.from_hour, self.to_hour)
        file_name  = dir_name + '/' + self.conn_file
        if os.path.exists(self.CONN_LOG.format(self.from_hour, self.to_hour)):
            print('Previous file found,.....removed!!!')
            os.remove(self.CONN_LOG.format(self.from_hour, self.to_hour))
        try:
            print('fetching data from sensor.......')
            cmd = "scp -3 172.16.4.73:/opt/zeek/logs/"+file_name+" /home/ctguser1/cogito-ml/ML/Anomaly_detection/real_fast_longConn/data/"+self.conn_file
            call(cmd.split(" "))

            print('Downloaded file size {}MB '.format(os.stat(self.CONN_LOG.format(self.from_hour, self.to_hour)).st_size/1e+6))

            return True
        except Exception as e:
            print(e)
            return False
        else:
            return False

if __name__ == '__main__':
    longConn = LongConn()

    if longConn.get_data_from_sensor():
        print(longConn.detect('data/conn.log', amountanom=100))
