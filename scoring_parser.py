from StreamingPhish.service import phishService
from freq_master.freq import FreqCounter
from User_agent.User_agent_detection import detect_single,analyze_user_agents_detect
import pandas as pd
# from sklearn.externals import joblib
import joblib
import numpy as np

phishservice = phishService()
freq = FreqCounter()
freq.load('freq_master/table.freq')
def dga(input):
    dns = freq.get_domain(input)
    #freq.save('freq_master/table.freq')
    if freq.probability(dns)[0] > 5:
        return 'safe'
    else:
        print('unsafe')
        return 'unsafe'

#load data
#ssl_logs = joblib.load('F:\\IESCO_complete_dec_may\\ssl pickle\\ssl.pkl')
http_log = joblib.load('F:\\IESCO_complete_dec_may\\http pickle\\http.pkl')
dns_logs = joblib.load('F:\\IESCO_complete_dec_may\\dns pickle\\dns.pkl')

#preprocessing
http_log = http_log[['host','user_agent','id.orig_h','id.resp_h']].dropna()
dns_logs = dns_logs[['query','id.orig_h','id.resp_h']].dropna()
# dns_logs = dns_logs.iloc[1:100]

def score_http(df):
    import swifter
    try:
        df = df.copy()
        df['phish'] = df['host'].swifter.apply(lambda x: phishservice.classify([x]))
        df['bot'] = df['user_agent'].swifter.apply(lambda x: detect_single(x))
        df['dga_http'] = df['host'].swifter.apply(lambda x: dga(x))
        return df
    except:
        return None
def score_dns(df):
    import swifter

    df['dga_dns'] = df['query'].swifter.apply(lambda x: dga(x))
    return df
splits = np.split(http_log.iloc[http_log.shape[0] % 8:, :], 8)
splits_dns = np.split(dns_logs.iloc[dns_logs.shape[0] % 8:, :], 8)

from joblib import delayed,Parallel
list_df = Parallel(n_jobs=8)(delayed(score_http)(i) for i in splits)
df_http_score = pd.concat(list_df, axis=0)

joblib.dump(df_http_score,'http_score.pkl')

list_df = Parallel(n_jobs=8)(delayed(score_dns)(i) for i in splits_dns)
df_dns_score = pd.concat(list_df, axis=0)

df_dns_score.to_csv('dns_score.csv')
