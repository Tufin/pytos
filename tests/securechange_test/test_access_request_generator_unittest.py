#!/opt/tufin/securitysuite/ps/python/bin/python3.4

import tempfile
import unittest
import xml.etree.ElementTree as ET

from pytos.common.logging.Logger import setup_loggers
from pytos.common.functions.Config import Secure_Config_Parser
from pytos.securechange.helpers import Access_Request_Generator

conf = Secure_Config_Parser()

LOGGER = setup_loggers(conf.dict("log_levels"), log_dir_path="/var/log/ps/tests")

# Csv files definitions.
valid_csv_file_1 = b'''
#CSV Header:
#Target,Source,Destination,Service,Action,Comment
#The supplied hostname/IP address will replace the $hostname parameter.
#Subnets can be input in CIDR notation or Dotted Quad notation.
#ANY,$hostname,192.168.123.0/24,ANY,Accept,Allow $hostname to access subnet 192.168.123.0/24
ANY,$hostname,10.1.1.1/255.255.255.255,TCP 53,Accept,Allow $hostname to access the 10.1.1.1 DNS server via TCP
ANY,$hostname,10.1.1.1/32,UDP 53,Accept,Allow $hostname to access the 10.1.1.1 DNS server via UDP
#ANY,ANY,$hostname,TCP 22,Drop, Block all SSH traffic to $hostname
'''
num_of_rules_in_csv_1 = 2
host_name_csv_1 = "1.1.1.1"
host_netmask_csv_1 = "255.255.255.255"
host_name_type_csv_1 = "IPV4"

valid_csv_file_2 = b'''
#CSV Header:
#Target,Source,Destination,Service,Action,Comment
#The supplied hostname/IP address will replace the $hostname parameter.
#Subnets can be input in CIDR notation or Dotted Quad notation.
ANY,$hostname,192.168.123.0/24,ANY,Accept,Allow $hostname to access subnet 192.168.123.0/24
ANY,$hostname,10.1.1.1/255.255.255.255|11.2.2.2/255.255.255.0,TCP 53,Accept,Allow $hostname to access the 10.1.1.1 DNS server via TCP
Cisco,$hostname,10.1.1.1/32,UDP 53,Accept,Allow $hostname to access the 10.1.1.1 DNS server via UDP
ANY,ANY,$hostname,TCP 22,Drop, Block all SSH traffic to $hostname
'''
num_of_rules_in_csv_2 = 4
host_name_csv_2 = "2.2.2.2/24"
host_netmask_csv_2 = "255.255.255.0"
host_name_type_csv_2 = "IPV4_WITH_MASK"


# Tuple lists definitions.
# (targets,sources,destinations,services,action,comment).
rule_tuples_1 = [(['ANY'],['ANY'],['ANY'],['ANY'], 'Accept', 'Allow everyone access to anywhere.'),
               (['ANY'],['1.1.1.1'],['10.1.1.1/255.255.255.0'],['TCP 53'], 'Drop', 'Block access from 1.1.1.1 to 10.1.1.1/24.')]
rule_tuples_2 = [(['ANY'],['ANY'],['2.2.2.2'],['ICMP'], 'remove', 'Bake me a cake.')]
invalid_rule_tuples_1 = [([''],['ANY'],['ANY'],['ANY'],'ANY','ANY')]
invalid_rule_tuples_2 = [(['ANY'],[''],['ANY'],['ANY'],'ANY','ANY')]
invalid_rule_tuples_3 = [(['ANY'],['ANY'],[''],['ANY'],'ANY','ANY')]
invalid_rule_tuples_4 = [(['ANY'],['ANY'],['ANY'],[''],'ANY','ANY')]
invalid_rule_tuples_5 = [(['ANY'],['ANY'],['ANY'],['ANY'],'','ANY')]

expected_multi_requests = [{'targets': [{'type': 'ANY'}],
                            'sources': [{'type': 'IP',
                                         'ip_address': '1.1.1.1',
                                         'netmask': '255.255.255.255'}],
                            'destinations': [{'type': 'IP',
                                              'ip_address': '192.168.123.0',
                                              'netmask': '255.255.255.0'}],
                            'services': [{'type': 'ANY'}],
                            'action': 'Accept',
                            'comment': 'Allow 1.1.1.1 to access subnet 192.168.123.0/24'},
                           {'targets': [{'type': 'ANY'}],
                            'sources': [{'type': 'IP',
                                         'ip_address': '1.1.1.1',
                                         'netmask': '255.255.255.255'}],
                            'destinations': [{'type': 'IP',
                                              'ip_address': '10.1.1.1',
                                              'netmask': '255.255.255.255'},
                                             {'type': 'IP',
                                              'ip_address': '11.2.2.2',
                                              'netmask': '255.255.255.0'}],
                            'services': [{'type': 'PROTOCOL',
                                          'port': '53',
                                          'protocol': 'TCP'}],
                            'action': 'Accept',
                            'comment': 'Allow 1.1.1.1 to access the 10.1.1.1 DNS server via TCP'},
                           {'targets': [{'type': 'Object',
                                         'management_name': 'Cisco'}],
                            'sources': [{'type': 'IP',
                                         'ip_address': '1.1.1.1',
                                         'netmask': '255.255.255.255'}],
                            'destinations': [{'type': 'IP',
                                              'ip_address': '10.1.1.1',
                                              'netmask': '255.255.255.255'}],
                            'services': [{'type': 'PROTOCOL',
                                          'port': '53',
                                          'protocol': 'UDP'}],
                            'action': 'Accept',
                            'comment': 'Allow 1.1.1.1 to access the 10.1.1.1 DNS server via UDP'},
                           {'targets': [{'type': 'ANY'}],
                            'sources': [{'type': 'ANY'}],
                            'destinations': [{'type': 'IP',
                                              'ip_address': '1.1.1.1',
                                              'netmask': '255.255.255.255'}],
                            'services': [{'type': 'PROTOCOL',
                                          'port': '22',
                                          'protocol': 'TCP'}],
                            'action': 'Drop',
                            'comment': 'Block all SSH traffic to 1.1.1.1'}]


class Test_Access_Request_Generator(unittest.TestCase):

    # Access request object for tests of create_multi_access_requests method
    def access_requests(self):
        csv_file = tempfile.NamedTemporaryFile()
        csv_file.file.write(valid_csv_file_2)
        csv_file.file.close()
        requests = Access_Request_Generator.from_csv_file(csv_file.name, '1.1.1.1')
        return requests.create_multi_access_requests()

    #-----------------------------------------------#
    # Tests of "from_csv_file" method               #
    #-----------------------------------------------#

    def test_from_csv_file_FOR_valid_file_1(self):
        LOGGER.debug("Hello. My name is Inigo Montoya. You killed my father. Prepare to die.")

        # Creating temporary csv file
        csv_file_wrapper = tempfile.NamedTemporaryFile()
        csv_file_wrapper.file.write(valid_csv_file_1)
        csv_file_wrapper.file.close()

        request = Access_Request_Generator.from_csv_file(csv_file_wrapper.name, host_name_csv_1)
        host_name_csv_1_without_mask = host_name_csv_1.split('/')[0]

        assert len(request.rules) == num_of_rules_in_csv_1
        assert request.rules[0] == {'comment': 'Allow {} to access the 10.1.1.1 DNS server via TCP'.format(host_name_csv_1),
                                    'destinations': [{'netmask': '255.255.255.255',
                                                      'address': '10.1.1.1',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'targets': ['ANY'],
                                    'sources': [{'netmask': host_netmask_csv_1,
                                                 'address': host_name_csv_1_without_mask,
                                                 'type': host_name_type_csv_1}],
                                    'services': [{'port': '53',
                                                  'protocol': 'TCP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Accept'}
        assert request.rules[1] == {'comment': 'Allow {} to access the 10.1.1.1 DNS server via UDP'.format(host_name_csv_1),
                                    'destinations': [{'netmask': '255.255.255.255',
                                                      'address': '10.1.1.1',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'targets': ['ANY'],
                                    'sources': [{'netmask': host_netmask_csv_1,
                                                 'address': host_name_csv_1_without_mask,
                                                 'type': host_name_type_csv_1}],
                                    'services': [{'port': '53',
                                                  'protocol': 'UDP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Accept'}
        csv_file_wrapper.close()

    def test_from_csv_file_FOR_valid_file_2(self):
        # Creating temporary csv file
        csv_file_wrapper = tempfile.NamedTemporaryFile()
        csv_file_wrapper.file.write(valid_csv_file_2)
        csv_file_wrapper.file.close()

        request = Access_Request_Generator.from_csv_file(csv_file_wrapper.name, host_name_csv_2)
        host_name_csv_2_without_mask = host_name_csv_2.split('/')[0]

        assert len(request.rules) == num_of_rules_in_csv_2
        assert request.rules[0] == {'comment': 'Allow {} to access subnet 192.168.123.0/24'.format(host_name_csv_2),
                                    'destinations': [{'netmask': '255.255.255.0',
                                                      'address': '192.168.123.0',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'targets': ['ANY'],
                                    'sources': [{'netmask': host_netmask_csv_2,
                                                 'address': host_name_csv_2_without_mask,
                                                 'type': host_name_type_csv_2}],
                                    'services': [{'type': 'ANY'}],
                                    'action': 'Accept'}
        assert request.rules[1] == {'comment': 'Allow {} to access the 10.1.1.1 DNS server via TCP'.format(host_name_csv_2),
                                    'destinations': [{'netmask': '255.255.255.255',
                                                      'address': '10.1.1.1',
                                                      'type': 'IPV4_WITH_MASK'},
                                                     {'netmask': '255.255.255.0',
                                                      'address': '11.2.2.2',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'targets': ['ANY'],
                                    'sources': [{'netmask': host_netmask_csv_2,
                                                 'address': host_name_csv_2_without_mask,
                                                 'type': host_name_type_csv_2}],
                                    'services': [{'port': '53',
                                                  'protocol': 'TCP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Accept'}
        assert request.rules[2] == {'comment': 'Allow {} to access the 10.1.1.1 DNS server via UDP'.format(host_name_csv_2),
                                    'destinations': [{'netmask': '255.255.255.255',
                                                      'address': '10.1.1.1',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'targets': ['Cisco'],
                                    'sources': [{'netmask': host_netmask_csv_2,
                                                 'address': host_name_csv_2_without_mask,
                                                 'type': host_name_type_csv_2}],
                                    'services': [{'port': '53',
                                                  'protocol': 'UDP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Accept'}
        assert request.rules[3] == {'comment': 'Block all SSH traffic to {}'.format(host_name_csv_2),
                                    'destinations': [{'netmask': host_netmask_csv_2,
                                                      'address': host_name_csv_2_without_mask,
                                                      'type': host_name_type_csv_2}],
                                    'targets': ['ANY'],
                                    'sources': [{'netmask': None,
                                                 'address': None,
                                                 'type': 'ANY'}],
                                    'services': [{'port': '22',
                                                  'protocol': 'TCP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Drop'}
        csv_file_wrapper.close()

    def test_from_csv_file_FOR_none_existent_file(self):
        try:
            request = Access_Request_Generator.from_csv_file("/opt/tufin/securitysuite/None/Existent/File", 'Host Name')
        except FileNotFoundError as file_exception:
            assert isinstance(file_exception, FileNotFoundError)

    #-----------------------------------------------#
    # Tests of "from_list_of_tuples" method         #
    #-----------------------------------------------#

    def test_from_list_of_tuples_FOR_valid_rule_tuples_1(self):
        request = Access_Request_Generator.from_list_of_tuples(rule_tuples_1)
        assert len(request.rules) == 2
        assert request.rules[0] == {'targets': ['ANY'],
                                    'sources': [{'netmask': None,
                                                 'address': None,
                                                 'type': 'ANY'}],
                                    'destinations': [{'netmask': None,
                                                      'address': None,
                                                      'type': 'ANY'}],
                                    'services': [{'type': 'ANY'}],
                                    'action': 'Accept',
                                    'comment': 'Allow everyone access to anywhere.'}

        assert request.rules[1] == {'targets': ['ANY'],
                                    'sources': [{'netmask': '255.255.255.255',
                                                 'address': '1.1.1.1',
                                                 'type': 'IPV4'}],
                                    'destinations': [{'netmask': '255.255.255.0',
                                                      'address': '10.1.1.1',
                                                      'type': 'IPV4_WITH_MASK'}],
                                    'services': [{'port': '53',
                                                  'protocol': 'TCP',
                                                  'type': 'PROTOCOL'}],
                                    'action': 'Drop',
                                    'comment': 'Block access from 1.1.1.1 to 10.1.1.1/24.'}

    def test_from_list_of_tuples_FOR_valid_rule_tuples_2(self):
        request = Access_Request_Generator.from_list_of_tuples(rule_tuples_2)
        assert len(request.rules) == 1
        assert request.rules[0] == {'targets': ['ANY'],
                                    'sources': [{'netmask': None,
                                                 'address': None,
                                                 'type': 'ANY'}],
                                    'destinations': [{'netmask': '255.255.255.255',
                                                      'address': '2.2.2.2',
                                                      'type': 'IPV4'}],
                                    'services': [{'type': 'ICMP'}],
                                    'action': 'remove',
                                    'comment': 'Bake me a cake.'}
        LOGGER.critical(request.create_multi_access_requests()[0].to_xml_string())

    def test_from_list_of_tuples_FOR_invalid_rule_tuples_1(self):
        LOGGER.debug("Testing for invalid rule tuples 1")
        request = Access_Request_Generator.from_list_of_tuples(invalid_rule_tuples_1)

    def test_from_list_of_tuples_FOR_invalid_rule_tuples_2(self):
        LOGGER.debug("Testing for invalid rule tuples 2")
        request = Access_Request_Generator.from_list_of_tuples(invalid_rule_tuples_2)

    def test_from_list_of_tuples_FOR_invalid_rule_tuples_3(self):
        LOGGER.debug("Testing for invalid rule tuples 3")
        request = Access_Request_Generator.from_list_of_tuples(invalid_rule_tuples_3)

    def test_from_list_of_tuples_FOR_invalid_rule_tuples_4(self):
        LOGGER.debug("Testing for invalid rule tuples 4")
        try:
            request = Access_Request_Generator.from_list_of_tuples(invalid_rule_tuples_4)
        except ValueError as service_error:
            assert isinstance(service_error, ValueError)

    def test_from_list_of_tuples_FOR_invalid_rule_tuples_5(self):
        LOGGER.debug("Testing for invalid rule tuples 5")
        request = Access_Request_Generator.from_list_of_tuples(invalid_rule_tuples_5)


    #-----------------------------------------------#
    # Tests of "create_multi_access_requests" method#
    #-----------------------------------------------#

    def test_create_multi_access_requests(self):
        access_requests = self.access_requests()
        # access request no.1
        trees = [ET.fromstring(rule.to_xml_string()) for rule in access_requests]
        for tree in trees:
            LOGGER.debug('\n' + ET.tostring(tree).decode('ascii'))
        for rule_num, rule in enumerate(trees):
            # Asserting request number/name.
            assert rule.find('order').text == 'AR{}'.format(rule_num + 1)

            # Asserting the targets of the request.
            for tar_num, target in enumerate(rule.find('targets').iter('target')):
                if target.get('type') == 'ANY':
                    assert target.get('type') == expected_multi_requests[rule_num]['targets'][tar_num]['type']
                else:
                    assert target.get('type') == expected_multi_requests[rule_num]['targets'][tar_num]['type']
                    assert target.find('management_name').text == expected_multi_requests[rule_num]['targets'][tar_num]['management_name']

            # Asserting the sources of the request.
            for src_num, source in enumerate(rule.find('sources').iter('source')):
                if source.get('type') == 'ANY':
                    assert source.get('type') == expected_multi_requests[rule_num]['sources'][src_num]['type']
                else:
                    assert source.get('type') == expected_multi_requests[rule_num]['sources'][src_num]['type']
                    assert source.find('ip_address').text == expected_multi_requests[rule_num]['sources'][src_num]['ip_address']
                    assert source.find('netmask').text == expected_multi_requests[rule_num]['sources'][src_num]['netmask']

            # Asserting the destinations of the request.
            for dst_num, destination in enumerate(rule.find('destinations').iter('destination')):
                if destination.get('type') == 'ANY':
                    assert destination.get('type') == expected_multi_requests[rule_num]['destinations'][dst_num]['type']
                else:
                    assert destination.get('type') == expected_multi_requests[rule_num]['destinations'][dst_num]['type']
                    assert destination.find('ip_address').text == expected_multi_requests[rule_num]['destinations'][dst_num]['ip_address']
                    assert destination.find('netmask').text == expected_multi_requests[rule_num]['destinations'][dst_num]['netmask']

            # Asserting the services of the request.
            for srv_num, service in enumerate(rule.find('services').iter('service')):
                if service.get('type') == 'ANY':
                    assert service.get('type') == expected_multi_requests[rule_num]['services'][srv_num]['type']
                else:
                    assert service.get('type') == expected_multi_requests[rule_num]['services'][srv_num]['type']
                    assert service.find('port').text == expected_multi_requests[rule_num]['services'][srv_num]['port']
                    assert service.find('protocol').text == expected_multi_requests[rule_num]['services'][srv_num]['protocol']

            # Asserting the action of the request.
            assert rule.find('action').text == expected_multi_requests[rule_num]['action']

            # Asserting the comment of the request.
            assert rule.find('comment').text == expected_multi_requests[rule_num]['comment']


if __name__ == '__main__':
    unittest.main()
