#!/opt/tufin/securitysuite/ps/python/bin/python3.4

import sys

from pytos.securetrack.xml_objects import rest
import xml.etree.ElementTree as ET
from pytos.common import tufin_logger
from pytos.common.functions.config import Secure_Config_Parser
import unittest

conf = Secure_Config_Parser()

LOGGER = tufin_logger.setup_loggers(conf.dict("log_levels"), log_dir_path="/var/log/ps/tests")

DEVICE_XML = '''<?xml version="1.0" encoding="UTF-8"?><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>555</id><name>ami</name><offline>false</offline><topology>true</topology><ip>192.168.1.19</ip><latest_revision>18007</latest_revision></device>'''

DEVICES_LIST_XML = '''<?xml version="1.0" encoding="UTF-8"?><devices><count>31</count><total>31</total><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7850</id><name>US_OH_CL1</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>15</domain_id><domain_name>Americas</domain_name><id>7805</id><name>US_OH_FW2</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7852</id><name>US_OH_FW2</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7842</id><name>tami</name><offline>false</offline><topology>true</topology></device><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7838</id><name>US_OH_CL1</name><offline>false</offline><topology>true</topology></device><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7841</id><name>Cluster1</name><offline>false</offline><topology>true</topology></device><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7847</id><name>Cluster1</name><offline>false</offline><topology>true</topology></device><device><model>junos</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7551</id><name>Core-Switch</name><offline>false</offline><topology>true</topology></device><device><model>nsm</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7858</id><name>NSM 2</name><offline>false</offline><topology>false</topology></device><device><model>nsm_device</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7860</id><name>NSM 2-SRX100</name><offline>false</offline><topology>false</topology></device><device><model>cp_smrt_cntr</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>553</id><name>Hercules_new</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>439</id><name>hercules</name><offline>false</offline><topology>true</topology></device><device><model>PaloAltoFW</model><vendor>PaloAltoNetworks</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7865</id><name>PA-Oran-Test-Do-Not-Remove</name><offline>false</offline><topology>true</topology></device><device><model>netscreen</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7863</id><name>SSG</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>555</id><name>ami</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>556</id><name>tami</name><offline>false</offline><topology>true</topology></device><device><model>nsm_device</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7859</id><name>NSM 2-SSG</name><offline>false</offline><topology>false</topology></device><device><model>nsm_device</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7861</id><name>NSM 2-srx100_domainJunos</name><offline>false</offline><topology>false</topology></device><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>554</id><name>Cluster1</name><offline>false</offline><topology>true</topology></device><device><model>module_cluster</model><vendor>Checkpoint</vendor><domain_id>15</domain_id><domain_name>Americas</domain_name><id>7803</id><name>US_OH_CL1</name><offline>false</offline><topology>true</topology></device><device><model>cp_smrt_cntr</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>1</id><name>Hercules</name><offline>false</offline><topology>false</topology></device><device><model>nsm_device</model><vendor>Netscreen</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7862</id><name>NSM 2-Cluster</name><offline>false</offline><topology>false</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>15</domain_id><domain_name>Americas</domain_name><id>7804</id><name>US_OH_FW1</name><offline>false</offline><topology>true</topology></device><device><model>cp_smrt_cntr</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7837</id><name>Hercules2</name><offline>false</offline><topology>false</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7840</id><name>US_OH_FW2</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7851</id><name>US_OH_FW1</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7839</id><name>US_OH_FW1</name><offline>false</offline><topology>true</topology></device><device><model>cp_smrt_cntr</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7846</id><name>SMC_R77</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7849</id><name>tami</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7848</id><name>ami</name><offline>false</offline><topology>true</topology></device><device><model>module</model><vendor>Checkpoint</vendor><domain_id>1</domain_id><domain_name>Default</domain_name><id>7843</id><name>ami</name><offline>false</offline><topology>true</topology></device></devices>'''


class Test_Secure_Track_XML(unittest.TestCase):
    def test_devices_list(self):
        devices_list_xml_node = ET.fromstring(DEVICES_LIST_XML)
        device_list = rest.Device.Devices_List.from_xml_node(devices_list_xml_node)
        assert device_list.count >= 0
        assert device_list.total >= 0
        assert device_list.total >= device_list.count
        assert device_list is not None
        for device in device_list:
            assert isinstance(device, rest.Device.Device)

    def test_device(self):
        device_xml_node = ET.fromstring(DEVICE_XML)
        device = rest.Device.Device.from_xml_node(device_xml_node)
        assert device.model is not None
        assert device.vendor is not None
        assert device.domain_name is not None
        assert device.domain_id is not None
        assert device.id is not None
        assert device.name is not None
        assert device.offline is not None
        assert device.topology is not None


if __name__ == '__main__':
    unittest.main()


