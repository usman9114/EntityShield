# project/test_basic.py
import os
import unittest
from service import app
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

    def measure(self, data):
        self.app.get('/', follow_redirects=True)
        return self.app.post(
            '/phishService',
            data=data,
            follow_redirects=True)

    def test_output(self):
        response = self.measure('amazon-services-com.gq,apple.com')
        print(response.data)
        self.assertEqual(response.status_code, 200)



if __name__ == "__main__":
    unittest.main()