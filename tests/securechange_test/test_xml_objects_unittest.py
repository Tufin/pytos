#!/opt/tufin/securitysuite/ps/python/bin/python3.4

import unittest

from pytos.securechange.xml_objects import rest, securechange_api
from pytos.common.functions.Config import Secure_Config_Parser
import xml.etree.ElementTree as ET
from pytos.common.logging.Logger import setup_loggers


with open('/opt/tufin/securitysuite/ps/tests/bin/Secure_Change_Test/ticket_info.xml') as f:
    TICKET_INFO_XML = f.read()

conf = Secure_Config_Parser()
LOGGER = setup_loggers(conf.dict("log_levels"), log_dir_path="/var/log/ps/tests")


class Test_Secure_Change_XML(unittest.TestCase):
    def test_01_ticket_info(self):
        ticket_info_xml_node = ET.fromstring(TICKET_INFO_XML)
        ticket_info = securechange_api.Ticket_Info(ticket_info_xml_node)
        assert int(ticket_info.id) >= 1
        assert ticket_info.createDate != ""
        assert ticket_info.updateDate != ""
        assert ticket_info.subject != ""

    def test_02_ticket(self):
        ticket_xml_string = open("/opt/tufin/securitysuite/ps/tests/resource/ticket_all_fields.xml").read()
        ticket = rest.Ticket.from_xml_string(ticket_xml_string)
        assert ticket.to_xml_doc() is not None


if __name__ == '__main__':
    unittest.main()

