import joblib
import pandas as pd

class uri_check:

    def __init__(self):
        self.vectorizer = joblib.load('uri_checker/vectorizer.pkl')#TfidfVectorizer(min_df = 0.0, analyzer="char", sublinear_tf=True, ngram_range=(1,3)) #converting data to vectors
        self.model = joblib.load('uri_checker/uri_checker.pkl')
        self.dic = {1:True, 0 :False}

    def predict(self, uri):
        df = pd.DataFrame(uri,columns=['uri'])
        X = self.vectorizer.transform(df['uri'].values)
        df['prediction'] = [self.dic[f] for f in self.model.predict(X)]

        # round(self.model.predict_proba(X)[0][self.model.predict(X)][0], 3)
        df['probability'] = [f.max() for f in self.model.predict_proba(X)]


        return {'uri':[f for f in df['uri']], 'is_malicious': [f for f in df['prediction']], 'probability': [f for f in df['probability']]}

if __name__ =='__main__':
    u = uri_check()
    print(u.predict(['/javascript/htpasswd.exe','/javascript/htpasswd.exe','/?cmdid=1&appid=1106545419']))