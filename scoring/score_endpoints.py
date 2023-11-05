"""Anomaly Detection Example"""

# from sklearn.externals import joblib
import joblib
import os

class scoring:

    def __init__(self):
        self.pie_pkl = joblib.load(os.path.join('scoring','feature_sets', 'pie_chart_score.pkl'))
        self.top_score = joblib.load(os.path.join('scoring','feature_sets', 'Top_risk_dataset.pkl'))

    def top_n_score(self):
        return self.top_score#.iloc[:n]

    def filter_ip_pie(self):
        return self.pie_pkl#[self.pie_pkl['IP Address']==ip]


if __name__ =='__main__':
    ad = scoring()
    print(ad.filter_ip_pie('172.16.2.211'))
    print(ad.top_n_score(10))
   # print(ad.predict())
