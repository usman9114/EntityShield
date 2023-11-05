"""LogToDataFrame: Converts a Zeek log to a Pandas DataFrame"""
from __future__ import print_function

# Third Party
import pandas as pd
from joblib import delayed, Parallel, dump
import os
import numpy as np
from model_training.model_generation_simple import getFeatures
# Local
# from zat import bro_log_reader
import time


class LogToDataFrame(object):
    """LogToDataFrame: Converts a Zeek log to a Pandas DataFrame
        Notes:
            This class has recently been overhauled from a simple loader to a more
            complex class that should in theory:
              - Select better types for each column
              - Should be faster
              - Produce smaller memory footprint dataframes
            If you have any issues/problems with this class please submit a GitHub issue.
        More Info: https://supercowpowers.github.io/zat/large_dataframes.html
    """
    def __init__(self):
        """Initialize the LogToDataFrame class"""

        # First Level Type Mapping
        #    This map defines the types used when first reading in the Zeek log into a 'chunk' dataframes.
        #    Types (like time and interval) will be defined as one type at first but then
        #    will undergo further processing to produce correct types with correct values.
        # See: https://stackoverflow.com/questions/29245848/what-are-all-the-dtypes-that-pandas-recognizes
        #      for more info on supported types.
        self.type_map = {'bool': 'category',  # Can't hold NaN values in 'bool', so we're going to use category
                         'count': 'Int64',
                         'int': 'Int64',
                         'double': 'float',
                         'time': 'float',      # Secondary Processing into datetime
                         'interval': 'float',  # Secondary processing into timedelta
                         'port': 'Int64'
                         }

    def _get_field_info(self, log_filename):
        """Internal Method: Use ZAT log reader to read header for names and types"""
        _bro_reader = bro_log_reader.BroLogReader(log_filename)
        _, field_names, field_types, _ = _bro_reader._parse_bro_header(log_filename)
        return field_names, field_types

    def _create_initial_df(self, log_filename, all_fields, usecols, dtypes):
        """Internal Method: Create the initial dataframes by using Pandas read CSV (primary types correct)"""
        return pd.read_csv(log_filename, sep='\t', names=all_fields, usecols=usecols, dtype=dtypes, comment="#", na_values='-')

    def create_dataframe(self, log_filename, ts_index=True, aggressive_category=True, usecols=None, logtype=None):
        """ Create a Pandas dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Zeek log
               ts_index (bool): Set the index to the 'ts' field (default = True)
               aggressive_category (bool): convert unknown columns to category (default = True)
               usecol (list): A subset of columns to read in (minimizes memory usage) (default = None)
        """

        print('Type {}'.format(logtype))
        keepCols = {
            'conn': ['ts', 'id.orig_h', 'id.resp_h', 'proto', 'id.resp_p', 'id.orig_p', 'orig_pkts', 'resp_pkts',
                     'resp_bytes', 'orig_bytes',
                     'duration', 'service', 'orig_ip_bytes', 'resp_ip_bytes'],
            'http': ['ts', 'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'method', 'resp_mime_types',
                     'request_body_len', 'host', 'uri'],
            'dns': ['id.orig_h', 'id.resp_h', 'ts', 'Z', 'id.orig_p', 'id.resp_p', 'proto', 'qtype_name', 'query',
                    'answers', 'rejected']}

        def write_csv_fast(chunk, logtype):
            chunk = chunk[keepCols[logtype]].dropna()
            # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
            for name, bro_type in zip(field_names, field_types):
                if bro_type == 'time':
                    chunk[name] = pd.to_datetime(chunk[name], unit='s')


            # Set the index
            if ts_index and not chunk.empty:
                chunk.set_index('ts', inplace=True)

            if logtype in ['conn', 'http', 'dns']:
                chunk.to_csv(os.path.join('features-set', logtype + '.csv'), mode='a')

        # Grab the field information
        field_names, field_types = self._get_field_info(log_filename)
        all_fields = field_names  # We need ALL the fields for later

        # If usecols is set then we'll subset the fields and types
        if usecols:
            # Usecols needs to include ts
            if 'ts' not in usecols:
                usecols.append('ts')
            field_types = [t for t, field in zip(field_types, field_names) if field in usecols]
            field_names = [field for field in field_names if field in usecols]

        # Get the appropriate types for the Pandas Dataframe
        pandas_types = self.pd_column_types(field_names, field_types, aggressive_category)

        # Now actually read in the initial dataframe
        self._df = pd.read_csv(log_filename, sep='\t', names=all_fields, usecols=usecols, comment="#", na_values='-',chunksize=500000)
        if logtype =='conn':
            df_train = pd.DataFrame()
            start_time = time.time()

            for i, chunk in enumerate(self._df):
                print('processing chunk # {}'.format(i))
                chunk = chunk[keepCols[logtype]].dropna()
                # Now we convert 'time' and 'interval' fields to datetime and timedelta respectively
                chunk['ts'] = pd.to_datetime(chunk['ts'], unit='s', errors='coerce')
                splits = np.array_split(chunk,8)#np.split(chunk.iloc[chunk.shape[0] % 8:, :], 8)
                print('done')
                list_df = Parallel(n_jobs=-1, verbose=10)(delayed(getFeatures)(i) for i in splits)
                df_train = pd.concat([pd.concat(list_df, axis=0), df_train])
            dump(df_train, 'features-set/con_featureset_v1-1.pkl')
            print("--- %s seconds ---" % (time.time() - start_time))


        else:
            for i, chunk in enumerate(self._df):
                print('processing chunk # {}'.format(i))
                splits = np.split(chunk.iloc[chunk.shape[0] % 8:, :], 8)
                print('skiping...{}'.format(chunk.shape[0] % 8))
                Parallel(n_jobs=-1, verbose=10)(delayed(write_csv_fast)(i, logtype) for i in splits)




    def pd_column_types(self, column_names, column_types, aggressive_category=True, verbose=False):
        """Given a set of names and types, construct a dictionary to be used
           as the Pandas read_csv dtypes argument"""

        # Agressive Category means that types not in the current type_map are
        # mapped to a 'category' if aggressive_category is False then they
        # are mapped to an 'object' type
        unknown_type = 'category' if aggressive_category else 'object'

        pandas_types = {}
        for name, bro_type in zip(column_names, column_types):

            # Grab the type
            item_type = self.type_map.get(bro_type)

            # Sanity Check
            if not item_type:
                # UID/FUID/GUID always gets mapped to object
                if 'uid' in name:
                    item_type = 'object'
                else:
                    if verbose:
                        print('Could not find type for {:s} using {:s}...'.format(bro_type, unknown_type))
                    item_type = unknown_type

            # Set the pandas type
            pandas_types[name] = item_type

        # Return the dictionary of name: type
        return pandas_types


# Simple test of the functionality
def test():
    """Test for LogToDataFrame Class"""
    import os
    pd.set_option('display.width', 1000)
    from zat.utils import file_utils

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    log_path = os.path.join(data_path, 'conn.log')

    # Convert it to a Pandas DataFrame
    log_to_df = LogToDataFrame()
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    # Test a bunch
    tests = ['app_stats.log', 'dns.log', 'http.log', 'notice.log', 'tor_ssl.log',
             'conn.log', 'dhcp_002.log', 'files.log',  'smtp.log', 'weird.log',
             'ftp.log',  'ssl.log', 'x509.log']
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print('Testing: {:s}...'.format(log_path))
        my_df = log_to_df.create_dataframe(log_path)
        print(my_df.head())
        print(my_df.dtypes)

    # Test out usecols arg
    conn_path = os.path.join(data_path, 'conn.log')
    my_df = log_to_df.create_dataframe(conn_path, usecols=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                                           'proto', 'orig_bytes', 'resp_bytes'])

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    my_df = log_to_df.create_dataframe(log_path)

    # Print out the head
    print(my_df.head())

    # Print out the datatypes
    print(my_df.dtypes)

    print('LogToDataFrame Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
