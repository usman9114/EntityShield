1. start by running service.py
2. flask endpoint localhost/phishService expects a post request
3. input body amazon-services-com.gq,apple.com (comma separated values)

output: Classification : input URL : probability of being phishing 

4. [
    "{amazon-services-com.gq: 0.78: Phishing}",
    "{apple.com: 0.00: Not Phishing}"
]