# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

import unittest
from app import create_app


class SdkTestCase(unittest.TestCase):

    def setUp(self):
        print("setUp....")
        app = create_app()
        app.config['TESTING'] = True
        app = app.test_client()
        self.app = app
        print("OK")

    def tearDown(self):
        print("tearDown....")
        self.test_clear_db()
        print("OK")

    def test_clear_db(self):
        response = self.app.get('/system/db/clear/')
        unittest.TestCase.assertEqual(self, response.status_code, 200)

if __name__ == '__main__':
    unittest.main()



