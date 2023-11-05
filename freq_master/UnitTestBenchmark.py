# project/test_basic.py
import os
import unittest
from freq import app
import json
class BasicTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.app = app.test_client()
        self.assertEqual(app.debug, False)

    def tearDown(self):
        pass

        ###############
        #### tests ####
        ###############

    def test_main_page(self):
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
    #
    def classify(self, data):
        #self.app.get('/', follow_redirects=True)
        return self.app.post(
            '/measure',
            data=json.dumps(data),
            follow_redirects=True)

    def test_update_method(self):
        response = self.app.get('/update?dns=cia', follow_redirects=True)
        print(response.data)
        self.assertEqual(response.status_code, 200)
    #

    #
    def test_output(self):
        with open('data/input/input.json') as myfile:
            j_data = json.loads(myfile.read())
        response = self.classify(j_data)
        print(response.data)
        self.assertEqual(response.status_code, 200)



if __name__ == "__main__":
    unittest.main()