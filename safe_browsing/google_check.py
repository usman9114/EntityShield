from pysafebrowsing import SafeBrowsing
from safe_browsing import CONST

class safebrowseurl():

    def __init__(self):
        self.s = SafeBrowsing(CONST.API_KEY)

    def __repr__(self):
        return 0
    def lookup_url(self,url):
        r = self.s.lookup_urls(url)
        return r
