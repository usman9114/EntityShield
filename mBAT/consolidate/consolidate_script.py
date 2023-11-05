#
import pandas as pd
import numpy as np
import os
import fileinput
import itertools
import glob
#
# """""""""""""""""""""""""UNZIPPING CODE """""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import shutil
import gzip
from os.path import join
import os
from consolidate.fireworks import LogToDataFrame
from zat import log_to_dataframe
import os

def run (base_path):
    # base_path = 'F:/logs'
    path_list = os.listdir(base_path)
    # path_lst = pd.to_datetime(path_list, errors='coerce').dropna()
    path_list = path_list[-2:]
    types = ['conn', 'http', 'dns']

    def gunzip_shutil(source_filepath, dest_filepath, block_size=65536):
        with gzip.open(source_filepath, 'rb') as s_file, \
                open(dest_filepath, 'wb') as d_file:
            shutil.copyfileobj(s_file, d_file, block_size)

    print('merging....')

    def consolidation(path, type, output):
        try:
            for folders in path_list:
                    try:
                        print(folders+' '+type)
                        for file in[f for f in os.listdir(os.path.join(path, folders)) if f.split('.')[0] == type]:
                            try:
                                gunzip_shutil(join(base_path, folders, file), join(base_path, folders, file.replace('.gz', '')))
                                with open(output+'.log', 'a+') as fout, fileinput.input(os.path.join(path, folders, file.replace('.gz', ''))) as fin:
                                    for line in fin:
                                        fout.write(line)
                            except:
                                pass
                    except Exception as e:
                        print(e)
                        pass
        except  Exception as e:
            print(e)

    if not os.path.exists('processed'):
        os.makedirs('processed')

    for i in types:
        consolidation(base_path, i, os.path.join('processed', i))



    def new_clear_dir(folder_name = 'conn'):
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        if  os.path.exists(folder_name):
            try:
                for f in os.listdir(folder_name):
                    os.remove(os.path.join(folder_name, f))
            except Exception as e:
                pass
    #
    keepCols = {'conn': ['ts', 'id.orig_h', 'id.resp_h', 'proto', 'id.resp_p', 'id.orig_p', 'orig_pkts', 'resp_pkts','resp_bytes','orig_bytes',
                      'duration', 'service','orig_ip_bytes','resp_ip_bytes'],
                     'http': ['ts', 'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'method', 'resp_mime_types',
                              'request_body_len', 'host', 'uri'],
                     'dns': ['id.orig_h', 'id.resp_h', 'ts', 'Z', 'id.orig_p', 'id.resp_p', 'proto', 'qtype_name', 'query',
                             'answers', 'rejected']}

    log_to_df = LogToDataFrame()
    for t in types:
        print(t)
        new_clear_dir(t)
        log_to_df.create_dataframe('processed/'+t+'.log', logtype=t, usecols=keepCols[t])



