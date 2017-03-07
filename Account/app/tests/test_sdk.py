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
        print("Setting Up")
        app = create_app()
        app.config['TESTING'] = True
        app = app.test_client()
        self.app = app

    def tearDown(self):
        pass

    def test_clear_db(self):
        response = self.app.get('/system/db/clear/salainen')
        unittest.TestCase.assertEqual(self, response.status_code, 200)

if __name__ == '__main__':
    unittest.main()



