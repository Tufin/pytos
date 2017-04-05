#!/opt/tufin/securitysuite/ps/python/bin/python3.4

import unittest

from pytos.common.logging.Logger import setup_loggers
from pytos.common.helpers import Secure_API_Helper
from pytos.common.functions.Config import Secure_Config_Parser

conf = Secure_Config_Parser()
LOGGER = setup_loggers(conf.dict("log_levels"), log_dir_path="/var/log/ps/tests")


class Test_Secure_API_Helper(unittest.TestCase):
    def test_01_cgi_login_cookie(self):
        helper = Secure_API_Helper.from_secure_config_parser(conf)
        assert helper._ensure_cgi_login_cookie()
        first_cookie = helper._login_cookie
        assert helper._login_cookie is not None
        assert helper._login_cookie != ""
        assert helper._get_cgi_login_cookie()
        assert helper._login_cookie != first_cookie


if __name__ == '__main__':
    unittest.main()
