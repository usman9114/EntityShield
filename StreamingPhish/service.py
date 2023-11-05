from joblib import load, dump
from StreamingPhish.phishing import PhishFeatures


class phishService:

    def __init__(self,db_ops):
        self.classifier = load('StreamingPhish/model/phish.pkl')
        # self.white_lst_path = 'StreamingPhish\model\whit_lst.pkl'
        self.db_ops = db_ops
        try:
            self.white_lst = self.db_ops.read_db('phishing_whitelist')
        except:
            self.white_lst = []
        self.phish = PhishFeatures()    # We need the compute_features() method to evaluate new data.
        self.LABEL_MAP = {0: "Not Phishing", 1: "Phishing"}
    def classify(self, url):
        try:
            features = self.phish.compute_features(url)
            prediction = self.classifier.predict_proba(features['values'])[:, 1] > 0.6
            prediction_scores = self.classifier.predict_proba(features['values'])[:, 1]

            results = []
            for domain, classification, score in zip(url, prediction, prediction_scores):
                if domain in self.white_lst:
                    res = "{}: {:.2f}: {}".format(domain, 0.0,'Not Phishing')
                    res = '{' +res + '}'
                    results.append(res)

                else:
                    res = "{}: {:.2f}: {}".format(domain, score, self.LABEL_MAP[classification])
                    res = '{' + res + '}'
                    results.append(res)
            return results
        except Exception as e:
            print(str)
            return None
    def update_white_lst(self):
        # if self.white_lst == []:
        #     dump(lst, self.white_lst_path)
        #     self.white_lst = lst
        # else:
        #     self.white_lst  = list(self.white_lst) + lst
        #     dump(self.white_lst.append(lst), self.white_lst_path)
        self.white_lst = self.db_ops.read_db('phishing_whitelist')





if __name__ == '__main__':
    wrapper = phishService()
    print('my_server up and running.....')
    app.run(debug=False, host='0.0.0.0', port=80, threaded=True)