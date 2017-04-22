#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import sys
import lxml.etree
import pytos
import os
import io
import tempfile
import time
import unittest
from unittest.mock import patch

from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.securetrack.xml_objects.rest.cleanups import Generic_Cleanup_List
from pytos.securetrack.xml_objects.rest.domain import Domains
from pytos.common.logging.logger import setup_loggers
from pytos.common.functions.config import Secure_Config_Parser
from pytos.common.exceptions import REST_Bad_Request_Error, REST_Not_Found_Error
from pytos.securetrack.xml_objects.rest import security_policy
from pytos.securetrack.xml_objects.base_types import Network_Object
from pytos.securetrack.xml_objects.rest.device import Device_Revision, Device, Devices_List, RuleSearchDeviceList
from pytos.securetrack.xml_objects.rest.rules import Rule_Documentation, Record_Set, Zone, Zone_Entry, Bindings_List, \
    Interfaces_List, Cleanup_Set, Rules_List, Network_Objects_List, Zone_List

test_data_dir = "/opt/tufin/securitysuite/ps/tests/bin/Secure_Track_Test/"

# existing device -  need to change these ID's when we'll have final version of the TOS for the testing suit
cisco_ASA_id = 1
cisco_router2801_id = 2
cisco_ASA_rules_UIDs = []
added_offline_device_id = 0
added_generic_device_id = 0
added_supported_device_id = 0
added_generic_device_name = ""
checkpoint_device_id = 5
offline_device_name = "offline"

default_domain_id = 1

security_policy_name = ""
security_policy_id = 0
# need to remove it when go to live

report_id = 0
dcr_id = 0

g_network_object = Network_Object(*(10 * [""]))
g_network_object_group = None
g_topology_edges_ids = []

g_service = None
g_service_group = None


def fake_request_response(rest_file):
    full_path = os.path.dirname(os.path.abspath(__file__))
    sub_resources_dir = sys._getframe(1).f_locals['self'].__class__.__name__.lower()
    resource_file = os.path.join(full_path, "resources", sub_resources_dir, "{}.xml".format(rest_file))
    with open(resource_file, mode='rb') as f:
        return f.read()


class TestDevices(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("127.0.0.1", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_by_id")
        device_by_id = self.helper.get_device_by_id(added_offline_device_id)
        self.assertIsInstance(device_by_id, Device)

    def test_02_get_devices_list(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_list")
        devices_list = self.helper.get_devices_list()
        self.assertIsInstance(devices_list, Devices_List)
        self.assertTrue(len(devices_list) == devices_list.count)
        self.assertTrue(devices_list.count > 0)

    def test_03_get_devices_list_with_custom_param(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_list")
        devices_list = self.helper.get_devices_list(custom_params={'vendor': 'cisco'})
        self.assertIsInstance(devices_list, Devices_List)
        self.assertEqual(len(devices_list), devices_list.count)
        self.assertTrue(devices_list.count > 0)

    def test_04_get_device_id_by_name(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_list")
        device_id = self.helper.get_device_id_by_name(device_name="Router 2801")
        self.assertTrue(device_id, 155)

        # assert invalid request - 2 devices with same name
        with self.assertRaises(IndexError):
            self.helper.get_device_id_by_name(device_name="ASA FireWall")

        # assert invalid request - Non existing device
        with self.assertRaises(ValueError):
            self.helper.get_device_id_by_name(device_name="NonExistingDeviceName")

    def test_05_get_cleanups_for_device_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("cleanups_by_device_id")
        cleanups = self.helper.get_cleanups_for_device_by_id(155)
        self.assertIsInstance(cleanups, Generic_Cleanup_List)
        self.assertTrue(len(cleanups) > 0)

    def test_06_failed_to_get_cleanups_for_device_by_id(self):
        self.mock_get_uri.return_value.status_code = 404
        self.mock_get_uri.return_value.content = fake_request_response("no_found_error")
        with self.assertRaises(ValueError):
            self.helper.get_cleanups_for_device_by_id(5555)

    def test_07_get_bindings_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_bindings")
        binding = self.helper.get_bindings_for_device(155)
        self.assertIsInstance(binding, Bindings_List)
        self.assertTrue(len(binding) > 0)

    def test_08_get_interfaces_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_interfaces")
        interfaces = self.helper.get_interfaces_for_device(155)
        self.assertIsInstance(interfaces, Interfaces_List)
        self.assertTrue(len(interfaces) > 0)

    def test_09_get_device_config(self):
        self.assertEqual(self.helper.get_device_config_by_id(added_offline_device_id), b'\x00')

    def test_10_add_offline_device(self):
        global added_offline_device_id
        self.mock_get_uri.return_value.status_code = 201
        self.mock_get_uri.return_value.headers = {'location': '1'}
        added_offline_device_id = self.helper.add_offline_device("TEST_DEVICE_123", "Cisco", "router")
        self.assertIsInstance(added_offline_device_id, int)

    # def test_11_upload_device_offline_config(self):
    #     with tempfile.NamedTemporaryFile(delete=False) as config_tempfile:
    #         config_tempfile.write(self.OFFLINE_TEST_DATA)
    #         config_temp_file_path = config_tempfile.name
    #     with open(config_temp_file_path) as config_tempfile:
    #         self.helper.upload_device_offline_config(added_offline_device_id, config_tempfile)
    #     os.remove(config_temp_file_path)


class TestRules(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("127.0.0.1", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_shadowed_rules(self):
        self.mock_get_uri.return_value.content = fake_request_response("cleanup_set")
        cleanup = self.helper.get_shadowed_rules_for_device_by_id(155)
        self.assertIsInstance(cleanup, Cleanup_Set)

    def test_02_get_rule_by_device_and_rule_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("rules")
        rules = self.helper.get_rule_by_device_and_rule_id(155, 1318013)
        self.assertEqual(rules[0].id, 1318013)

    def test_03_get_rules_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("rules")
        rules = self.helper.get_rules_for_device(155)
        self.assertIsInstance(rules, Rules_List)
        self.assertTrue(len(rules) > 0)

    def test_04_failed_to_get_rules_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("empty_rules")
        rules = self.helper.get_rules_for_device(155)
        self.assertIsInstance(rules, Rules_List)
        self.assertTrue(len(rules) == 0)

    def test_05_get_shadowing_rules_for_device_id_and_rule_uids(self):
        self.mock_get_uri.return_value.content = fake_request_response("cleanup_set")
        uid = "{53b95431-73ee-43de-a153-d299f4eb4804}"
        shadowing_rules = self.helper.get_shadowing_rules_for_device_id_and_rule_uids(155, uid)
        self.assertIsInstance(shadowing_rules, Cleanup_Set)

    def test_06_failed_get_shadowing_rules_for_device_id_and_rule_uids(self):
        self.mock_get_uri.return_value.content = fake_request_response("bad_request_error")
        self.mock_get_uri.return_value.status_code = 400
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_shadowing_rules_for_device_id_and_rule_uids(155, [])

    def test_07_get_devices_by_rule_search(self):
        self.mock_get_uri.return_value.content = fake_request_response("device_list_by_rule_search")
        devices = self.helper.get_devices_by_rule_search()
        self.assertIsInstance(devices, RuleSearchDeviceList)

    def test_08_rule_search_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("rules")
        rules = self.helper.rule_search_for_device(155)
        self.assertIsInstance(rules, Rules_List)
        self.assertTrue(len(rules) > 0)

    def test_09_get_rules_for_revision(self):
        self.mock_get_uri.return_value.content = fake_request_response("rules")
        rules = self.helper.get_rules_for_revision(1, True)
        self.assertIsInstance(rules, Rules_List)
        self.assertTrue(len(rules) > 0)

    def test_10_rule_documentation_format(self):
        src_xml = fake_request_response("rule_documentation")
        src_tree = lxml.etree.fromstring(src_xml)
        src_b = io.BytesIO()
        src_tree.getroottree().write_c14n(src_b)
        # create a new record set fot the rule documentation
        record_sets = [
            Record_Set("support@tufin.com", "admin", "2019-01-08T00:00:00+02:00", 1235, "this is a comment", "")
        ]
        rd = Rule_Documentation("admin", 'Comment for unittest suit', record_sets, '', True)
        dst_tree = lxml.etree.fromstring(rd.to_xml_string())
        dst_b = io.BytesIO()
        dst_tree.getroottree().write_c14n(dst_b)
        self.assertEqual(src_b.getvalue(), dst_b.getvalue())

    def test_11_get_rule_documentation_by_device_id_and_rule_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("rule_documentation")
        rd = self.helper.get_rule_documentation_by_device_id_and_rule_id(155, 1330304)
        self.assertIsInstance(rd, Rule_Documentation)

    def test_12_failed_to_get_rule_documentation_by_device_id_and_rule_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("not_found_error")
        self.mock_get_uri.return_value.status_code = 404
        with self.assertRaises(ValueError):
            self.helper.get_rule_documentation_by_device_id_and_rule_id(155, 1330303)

    def test_13_get_network_objects(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects_search")
        network_objects = self.helper.network_object_text_search("81.81.81.5", "any_field")
        self.assertIsInstance(network_objects, Network_Objects_List)


class TestZonesPoliciesAndRevisions(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("127.0.0.1", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200
        self.post_patcher = patch('pytos.common.rest_requests.requests.Request')
        self.mock_post_request = self.post_patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_zones(self):
        self.mock_get_uri.return_value.content = fake_request_response("zones")
        zones = self.helper.get_zones()
        self.assertIsInstance(zones, Zone_List)

    def test_02_post_zone(self):
        src_xml = fake_request_response("post_zone")
        src_tree = lxml.etree.fromstring(src_xml)
        src_b = io.BytesIO()
        src_tree.getroottree().write_c14n(src_b)
        comment = 'Name: {}, Created at: {}'.format("New Zone", "2017-04-22 10:09:18")
        zone_obj = Zone(None, "New Zone", comment)
        print(zone_obj.to_xml_string())
        dst_tree = lxml.etree.fromstring(zone_obj.to_xml_string())
        dst_b = io.BytesIO()
        dst_tree.getroottree().write_c14n(dst_b)
        self.assertEqual(src_b.getvalue(), dst_b.getvalue())

    def test_03_post_security_policy_matrix(self):
        # self.mock_get_uri.return_value.status_code = 201
        self.mock_get_uri.return_value.headers = {'location': '1'}
        self.mock_get_uri.return_value.content = fake_request_response("zones")
        security_policy_name = 'Some Policy Name'
        security_policy = {
            'internal': {
                'external': {
                    'severity': 'critical',
                    'access_type': 'ignored',
                    'allowed_services': ''
                }
            },
            'external': {
                'internal': {
                    'severity': 'high',
                    'access_type': 'restricted',
                    'allowed_services': 'https;Other 53;AOL;udp 88'
                }
            },
            'dmz': {
                'internal': {
                    'severity': 'critical',
                    'access_type': 'blocked',
                    'allowed_services': ''
                },
                'dmz': {
                    'severity': 'low',
                    'access_type': 'ignored',
                    'allowed_services': ''
                }
            }
        }
        policy_id = self.helper.post_security_policy_matrix(security_policy_name, security_policy)
        self.assertEqual(policy_id, 1)
        # body = b'--99a5063856d34d9fa0bca890ecb00e30\r\nContent-Disposition: form-data; name="security_policy_name"\r\n\r\nSome Policy Name\r\n--99a5063856d34d9fa0bca890ecb00e30\r\nContent-Disposition: form-data; name="file"; filename="security_policy"\r\nContent-Type: text/csv\r\n\r\nfrom zone,to zone,severity,access type,allowed services\r\ndmz,dmz,low,ignored,\r\ndmz,internal,critical,blocked,\r\nexternal,internal,high,restricted,https;Other 53;AOL;udp 88\r\ninternal,external,critical,ignored,\r\n\r\n--99a5063856d34d9fa0bca890ecb00e30--\r\n'
        # header = {'Content-Type': 'multipart/form-data; boundary=99a5063856d34d9fa0bca890ecb00e30', 'Content-Size': '501', 'Accept': '*/*'}
        # self.mock_post_request.assert_called_with("POST",
        #                                           "https://192.168.204.161/securetrack/api/security_policies",
        #                                           data=body,
        #                                           auth=('username', 'password'),
        #                                           headers=header)

    def test_02_post_put_delete_zone_entry(self):
        # taking only zones that are not the "internet zone"
        zones = [zone for zone in self.helper.get_zones() if zone.name != 'Internet']
        all_entries = []
        for zone in zones:
            all_entries.extend(self.helper.get_entries_for_zone_id(zone.id))
        all_ids = [entry.id for entry in all_entries]
        entry_id = len(all_ids) + 1
        entry_description = time.strftime('%Y-%m-%d %H:%M:%S')
        entry_ip = '1.1.1.{}'.format(entry_id)
        entry_negate = 0
        entry_mask = '255.255.255.255'

        zone_id = zones[-1].id
        zone_name = zones[-1].name
        entries = self.helper.get_entries_for_zone_id(zones[-1].id)
        zone_entry = Zone_Entry(entry_id, entry_description, entry_ip, entry_negate, entry_mask, zone_id)
        entry_id = self.helper.post_zone_entry(zone_entry.zoneId, zone_entry)
        time.sleep(2)
        entries = self.helper.get_entries_for_zone_id(zone_id)
        all_ids_returned = [entry.id for entry in entries]
        try:
            returned_entry = [entry for entry in entries if int(entry.id) == entry_id][0]
        except IndexError:
            message = ('failed to receive newly created entry with ID {} under zone ID {}.'.format(entry_id, zone_id) +
                       '\nAll entries ids received are:\n{}'.format(all_ids_returned))
            LOGGER.critical(message)
            raise IOError(message)
        self.assertTrue(returned_entry.comment == str(entry_description))
        self.assertTrue(returned_entry.ip == str(entry_ip))
        self.assertTrue(returned_entry.zoneId == zone_id)

        # Changes that are being made to the entry.
        entry_description = entry_description + '\n' + time.strftime('%Y-%m-%d %H:%M:%S') + ': Queued for deletion.'
        entry_ip = '101.101.101.101'.format(entry_id)
        entry_negate = 1
        entry_mask = '255.255.255.0'

        zone_entry = returned_entry
        zone_entry.comment = entry_description
        zone_entry.ip = entry_ip
        zone_entry.negate = entry_negate
        zone_entry.netmask = entry_mask
        self.helper.put_zone_entry(zone_id, zone_entry)
        time.sleep(2)
        entries = self.helper.get_entries_for_zone_id(zone_id)
        try:
            returned_entry = [entry for entry in entries if int(entry.id) == entry_id][0]
        except IndexError:
            message = 'Failed to receive newly modified entry with ID {} under zone ID {}'.format(entry_id, zone_id)
            LOGGER.critical(message)
            raise IOError(message)
        self.assertTrue(returned_entry.comment == str(entry_description))
        self.assertTrue(returned_entry.ip == str(entry_ip))
        self.assertTrue(returned_entry.netmask == str(entry_mask))
        self.assertTrue(returned_entry.zoneId == zone_id)

        self.helper.delete_zone_entry_by_zone_and_entry_id(zone_id, entry_id)
        entries = self.helper.get_entries_for_zone_id(zone_id)
        self.assertTrue(len([entry for entry in entries if entry.id == entry_id]) == 0)

    def test_03_get_zone_by_name(self):
        # assert valid request
        zone = self.helper.get_zone_by_name("dmz")
        self.assertIsInstance(zone, pytos.securetrack.xml_objects.rest.rules.Zone)
        self.assertEqual(zone.name, "dmz")

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_zone_by_name("NotExsistingZone")

    def test_04_get_entries_for_zones(self):
        # assert valid request
        zone_data = self.helper.get_entries_for_zones()
        self.assertIsInstance(zone_data, dict)
        self.assertTrue(zone_data)

        zone_entries = [x.zone_entries for x in zone_data.values() if x.zone_entries]

        self.assertIsInstance(zone_entries[0][0], pytos.securetrack.xml_objects.rest.rules.Zone_Entry)
        self.assertTrue(zone_entries[0][0].ip)

    def test_05_get_device_revisions_by_id(self):
        # assert an existing device
        revisions = self.helper.get_device_revisions_by_id(device_id=cisco_ASA_id)
        self.assertIsInstance(revisions, pytos.securetrack.xml_objects.rest.device.Device_Revisions_List)
        self.assertTrue(len(revisions) > 0)

        # assert non existing device - this should throw a ValueError but instead returns an empty result
        revisions = self.helper.get_device_revisions_by_id(device_id=55555)
        self.assertIsInstance(revisions, pytos.securetrack.xml_objects.rest.device.Device_Revisions_List)
        self.assertTrue(len(revisions) == 0)

        '''
        with self.assertRaises(ValueError):
            self.helper.get_device_revisions_by_id(device_id=55555)
        '''

    def test_06_get_policy_analysis(self):
        # assert valid request
        policy_analysis = self.helper.get_policy_analysis(cisco_ASA_id)
        self.assertIsInstance(policy_analysis, pytos.securetrack.xml_objects.rest.rules.Policy_Analysis_Query_Result)
        self.assertTrue(len(policy_analysis.devices_and_bindings) == 1)

        policy_analysis = self.helper.get_policy_analysis([cisco_ASA_id, cisco_router2801_id])
        self.assertIsInstance(policy_analysis, pytos.securetrack.xml_objects.rest.rules.Policy_Analysis_Query_Result)
        self.assertTrue(len(policy_analysis.devices_and_bindings) == 2)

        # assert invalid request
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_policy_analysis(5555)

    def test_07_get_security_policies(self):
        policies = self.helper.get_security_policies()
        self.assertIsInstance(policies, pytos.securetrack.xml_objects.rest.rules.Security_Policies_List)
        self.assertTrue(len(policies) > 0)

    def test_08_get_security_policy_by_name(self):
        global security_policy_id

        # assert valid request
        policy = self.helper.get_security_policy_by_name(security_policy_name, default_domain_id)
        self.assertIsInstance(policy, pytos.securetrack.xml_objects.rest.rules.Security_Policy)
        self.assertEqual(policy.name, security_policy_name)
        security_policy_id = policy.id

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_security_policy_by_name("NotExistingPolicy", default_domain_id)

    def test_09_get_security_policy_by_id(self):
        # assert valid request
        policy = self.helper.get_security_policy_by_id(security_policy_id, default_domain_id)
        self.assertIsInstance(policy, pytos.securetrack.xml_objects.rest.rules.Security_Policy)
        self.assertEqual(policy.id, security_policy_id)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_security_policy_by_id(5555, default_domain_id)

    def test_10_get_security_policy_matrix_csv(self):
        # assert valid request
        file = self.helper.get_security_policy_matrix_csv(security_policy_id)
        self.assertIsInstance(file, bytes)
        self.assertTrue(file)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_security_policy_matrix_csv(5555)

    def test_11_delete_security_policy_matrix(self):
        # assert valid request
        self.helper.delete_security_policy_matrix(security_policy_id)
        with self.assertRaises(ValueError):
            self.helper.get_security_policy_by_id(security_policy_id, default_domain_id)

        # assert invalid request
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.delete_security_policy_matrix(security_policy_id)

    def test_12_get_revision_by_id(self):
        # assert valid request
        revision = self.helper.get_revision_by_id(1)
        self.assertIsInstance(revision, Device_Revision)
        self.assertTrue(revision.id, 1)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_revision_by_id(9999)

    def test_13_get_revisions_base(self):
        revision_base = self.helper.get_revisions_base()
        self.assertIsInstance(revision_base, dict)
        self.assertTrue(len(revision_base) > 0)

    def test_14_get_policies_base(self):
        policies_base = self.helper.get_policies_base()
        self.assertIsInstance(policies_base, dict)
        self.assertTrue(len(policies_base) > 0)

    def test_15_get_security_policy_violations_for_all_devices(self):
        policy_violations = self.helper.get_security_policy_violations_for_all_devices()
        for device, device_violations in policy_violations.items():
            if device.name == offline_device_name:
                violations = device_violations["MEDIUM"]
                self.assertIsInstance(violations.violating_rules,
                                      pytos.securetrack.xml_objects.rest.rules.ViolatingRules)
                self.assertIsInstance(violations.violating_rules.violating_rule_list, list)
                self.assertTrue(len(violations.violating_rules.violating_rule_list) > 0)

    def test_16_get_security_policy_device_violations_by_severity(self):
        # assert valid requests
        device_id = self.helper.get_device_id_by_name(offline_device_name)
        violations = self.helper.get_security_policy_device_violations_by_severity(device_id,
                                                                                   "MEDIUM", "SECURITY_POLICY")
        self.assertIsInstance(violations.violating_rules, pytos.securetrack.xml_objects.rest.rules.ViolatingRules)
        self.assertIsInstance(violations.violating_rules.violating_rule_list, list)
        self.assertTrue(len(violations.violating_rules.violating_rule_list) > 0)

        # assert valid requests
        with self.assertRaises(REST_Not_Found_Error):
            self.helper.get_security_policy_device_violations_by_severity(5555, "MEDIUM", "SECURITY_POLICY")
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_security_policy_device_violations_by_severity(5555, "NotExistsSeverity", "SECURITY_POLICY")
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_security_policy_device_violations_by_severity(5555, "MEDIUM", "NotExistsSECURITY_POLICY")

    def test_17_get_policies_for_revision(self):
        # get revisions for device
        revisions = self.helper.get_device_revisions_by_id(device_id=checkpoint_device_id)
        self.assertIsInstance(revisions, pytos.securetrack.xml_objects.rest.device.Device_Revisions_List)
        self.assertTrue(len(revisions) > 0)

        # assert valid request
        policies = self.helper.get_policies_for_revision(revisions[0].id)
        self.assertIsInstance(policies, pytos.securetrack.xml_objects.rest.rules.Policy_List)
        self.assertTrue(len(policies) > 0)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_policies_for_revision(5555)

    def test_18_get_policies_for_device(self):
        # assert valid request
        policies = self.helper.get_policies_for_device(checkpoint_device_id)
        self.assertIsInstance(policies, pytos.securetrack.xml_objects.rest.rules.Policy_List)
        self.assertTrue(len(policies) > 0)

    def test_19_post_security_policy_exception(self):
        # assert valid request
        with open(test_data_dir + "exception.xml") as f:
            xml = f.read()

        policy_exception = security_policy.Security_Policy_Exception.from_xml_string(xml)
        self.helper.post_security_policy_exception(policy_exception)

        # assert invalid request - duplicate name
        with self.assertRaises(ValueError):
            self.helper.post_security_policy_exception(policy_exception)

    def test_20_delete_zone_by_zone_id(self):
        zone = self.helper.get_zone_by_name("external")
        # assert valid requests - delete zone without entries
        self.helper.delete_zone_by_zone_id(zone.id)
        with self.assertRaises(ValueError):
            self.helper.get_zone_by_name("external")

        zone = self.helper.get_zone_by_name("dmz")
        # assert valid requests - delete zone with entries
        self.helper.delete_zone_by_zone_id(zone.id, True)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_zone_by_name("dmz")

        with self.assertRaises(ValueError):
            self.helper.delete_zone_by_zone_id(5555)


class TestTopology(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                conf.get_password("securetrack")))

    def test_03_get_topology_interfaces(self):
        # assert valid request
        topology_interfaces = self.helper.get_topology_interfaces(cisco_ASA_id)
        self.assertIsInstance(topology_interfaces, pytos.securetrack.xml_objects.rest.rules.Topology_Interfaces_List)
        self.assertTrue(len(topology_interfaces) > 0)

        topology_interfaces = self.helper.get_topology_interfaces(5555)
        self.assertIsInstance(topology_interfaces, pytos.securetrack.xml_objects.rest.rules.Topology_Interfaces_List)
        self.assertTrue(len(topology_interfaces) == 0)

        # assert valid request
        with self.assertRaises(REST_Bad_Request_Error):
            # noinspection PyTypeChecker
            self.helper.get_topology_interfaces("NotValidRequest")


class TestReports(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                     conf.get_password("securetrack")))

    def test_04_post_dcr_test(self):
        global dcr_id
        with open(test_data_dir + "cisco_ASA.xml") as file:
            xml_string = file.read()
            dcr_test_id = self.helper.post_dcr_test(
                pytos.securetrack.xml_objects.rest.Audit.DCR_Test_Group.from_xml_string(xml_string))
            self.assertTrue(dcr_test_id)
            self.assertIsInstance(dcr_test_id, int)
            dcr_id = dcr_test_id

    def test_05_get_dcr_test_by_id(self):
        # assert valid request
        dcr = self.helper.get_dcr_test_by_id(dcr_id)
        self.assertIsInstance(dcr, pytos.securetrack.xml_objects.rest.Audit.DCR_Test_Group)
        self.assertEqual(int(dcr.id), dcr_id)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_dcr_test_by_id(1000)


class TestDomains(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                conf.get_password("securetrack")))

    def test_01_get_domains(self):
        domains = self.helper.get_domains()
        self.assertIsInstance(domains, Domains)
        self.assertTrue(domains[0].name, "Default")

    def test_02_get_domain_by_id(self):
        # assert valid request
        domain = self.helper.get_domain_by_id(default_domain_id)
        self.assertIsInstance(domain, pytos.securetrack.xml_objects.rest.domain.Domain)
        self.assertTrue(domain.name, "Default")

        # assert invalid request
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_domain_by_id(9999)


class TestNetworkObjects(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                     conf.get_password("securetrack")))

    def test_01_get_network_objects_for_device(self):
        global g_network_object
        global g_network_object_group

        # assert valid request
        network_objects = self.helper.get_network_objects_for_device(cisco_ASA_id)
        self.assertIsInstance(network_objects, pytos.securetrack.xml_objects.rest.rules.Network_Objects_List)
        self.assertTrue(len(network_objects) > 0)

        # save a single network object for later uses
        g_network_object = network_objects[0]
        # save a single network object group for later uses
        for network_object in network_objects:
            if network_object.type == "group" and len(network_object.members) > 1:
                g_network_object_group = network_object

        # assert invalid request
        network_objects = self.helper.get_network_objects_for_device(5555)
        self.assertIsInstance(network_objects, pytos.securetrack.xml_objects.rest.rules.Network_Objects_List)
        self.assertFalse(len(network_objects))

    def test_02_network_object_text_search(self):
        # assert valid request
        network_objects = self.helper.network_object_text_search("192.168", "any_field")
        self.assertIsInstance(network_objects, pytos.securetrack.xml_objects.rest.rules.Network_Objects_List)
        self.assertTrue(len(network_objects) > 0)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.network_object_text_search("", "")

    def test_03_network_object_subnet_search(self):
        # assert valid request
        network_objects = self.helper.network_object_subnet_search("192.168.0.0", "contained_in")
        self.assertIsInstance(network_objects, pytos.securetrack.xml_objects.rest.rules.Network_Objects_List)
        self.assertTrue(len(network_objects) > 0)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.network_object_subnet_search("", "")

    def test_04_get_network_objects(self):
        network_objects = self.helper.get_network_objects()
        self.assertIsInstance(network_objects, dict)
        self.assertTrue(len(network_objects) > 0)

    def test_05_get_network_object_by_device_and_object_id(self):
        # assert valid request
        network_object = self.helper.get_network_object_by_device_and_object_id(cisco_ASA_id, g_network_object.id)
        self.assertIsInstance(network_object, pytos.securetrack.xml_objects.rest.rules.Basic_Network_Object)
        self.assertTrue(network_object.id and network_object.name)

        # assert invalid requests
        with self.assertRaises(ValueError):
            self.helper.get_network_object_by_device_and_object_id(5555, g_network_object.id)

        with self.assertRaises(ValueError):
            self.helper.get_network_object_by_device_and_object_id(cisco_ASA_id, 55555)

    def test_06_get_member_network_objects_for_group_network_object(self):
        # assert valid request
        members = self.helper.get_member_network_objects_for_group_network_object(g_network_object_group, cisco_ASA_id)
        for member in members:
            self.assertIsInstance(member, (pytos.securetrack.xml_objects.rest.rules.Host_Network_Object,
                                           pytos.securetrack.xml_objects.rest.rules.Subnet_Network_Object))
            self.assertTrue(member.id and member.name)

        # assert invalid request
        with self.assertRaises(KeyError):
            self.helper.get_member_network_objects_for_group_network_object(g_network_object_group, 5555)
        with self.assertRaises(AttributeError):
            self.helper.get_member_network_objects_for_group_network_object(g_network_object, cisco_ASA_id)


class TestServices(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                conf.get_password("securetrack")))

    def test_01_get_services_for_device(self):
        global g_service
        global g_service_group

        # assert valid request
        services = self.helper.get_services_for_device(cisco_ASA_id)
        self.assertIsInstance(services, pytos.securetrack.xml_objects.rest.rules.Services_List)
        self.assertTrue(len(services) > 0)

        # save a single service for later uses
        g_service = services.services[0]
        # save a single service group for later uses
        for service in services:
            if service.type == "group" and len(service.members) > 1:
                g_service_group = service

        # assert invalid request
        services = self.helper.get_services_for_device(5555)
        self.assertIsInstance(services, pytos.securetrack.xml_objects.rest.rules.Services_List)
        self.assertFalse(len(services))

    def test_02_get_service_for_device_by_name(self):
        # assert valid request
        service = self.helper.get_service_for_device_by_name(cisco_ASA_id, g_service.display_name)
        self.assertIsInstance(service, pytos.securetrack.xml_objects.rest.rules.Single_Service)
        self.assertTrue(service)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_service_for_device_by_name(cisco_ASA_id, "NotExsistingService")

    def test_03_get_service_by_device_and_object_id(self):
        # assert valid request
        service = self.helper.get_service_by_device_and_object_id(cisco_ASA_id, g_service.id)
        self.assertIsInstance(service, pytos.securetrack.xml_objects.rest.rules.Single_Service)
        # self.assertTrue(service.name, "!80 (tcp)")
        self.assertTrue(service.name, g_service.name)

        # assert invalid request
        with self.assertRaises(ValueError):
            self.helper.get_service_by_device_and_object_id(cisco_ASA_id, 9999999)
        with self.assertRaises(ValueError):
            self.helper.get_service_by_device_and_object_id(0, 467677)

    def test_04_get_member_services_for_group_service(self):
        # assert valid request
        member_services = self.helper.get_member_services_for_group_service(g_service_group, cisco_ASA_id)
        for member in member_services:
            self.assertIsInstance(member, pytos.securetrack.xml_objects.rest.rules.Single_Service)
            self.assertTrue(member.id and member.name)

        # assert valid request
        with self.assertRaises(KeyError):
            self.helper.get_member_services_for_group_service(g_service_group, 5555)
        with self.assertRaises(AttributeError):
            self.helper.get_member_services_for_group_service(g_service, cisco_ASA_id)


class TestGeneralSettings(unittest.TestCase):
    def setUp(self):
        self.helper = pytos.securetrack.helpers.Secure_Track_Helper(conf.get("securetrack", "hostname"),
                                                                    (conf.get_username("securetrack"),
                                                                     conf.get_password("securetrack")))

    def test_03_get_change_authorization_status(self):
        # get revisions for device
        revisions = self.helper.get_device_revisions_by_id(device_id=cisco_ASA_id)
        self.assertIsInstance(revisions, pytos.securetrack.xml_objects.rest.device.Device_Revisions_List)
        self.assertTrue(len(revisions) > 1)

        # sort the revision by id
        revisions = sorted(revisions, key=lambda x: x.date, reverse=False)
        # get the old and new version we want to check
        old_revision = revisions[0]
        new_revision = revisions[1]

        # assert valid request
        status = self.helper.get_change_authorization_status(old_revision.id, new_revision.id)
        self.assertIsInstance(status.new_revision, pytos.securetrack.xml_objects.rest.device.Device_Revision)
        self.assertIsInstance(status.old_revision, pytos.securetrack.xml_objects.rest.device.Device_Revision)
        self.assertIsInstance(status.change_authorization_bindings,
                              pytos.securetrack.xml_objects.rest.rules.ChangeAuthorizationBindings)
        self.assertTrue(status.old_revision.id and status.new_revision.id)

        # assert invalid request
        with self.assertRaises(REST_Not_Found_Error):
            self.helper.get_change_authorization_status(9999, 9999)


if __name__ == '__main__':
    unittest.main()
