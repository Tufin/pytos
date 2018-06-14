#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import sys
import lxml.etree
import os
import io
import unittest
from unittest.mock import patch

from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.securetrack.xml_objects.rest.cleanups import Generic_Cleanup_List
from pytos.securetrack.xml_objects.rest.domain import Domains, Domain
from pytos.common.exceptions import REST_Bad_Request_Error, REST_Not_Found_Error
from pytos.securetrack.xml_objects.rest import security_policy
from pytos.securetrack.xml_objects.rest.device import Device_Revision, Device, Devices_List, RuleSearchDeviceList, \
    Device_Revisions_List
from pytos.securetrack.xml_objects.rest.nat_rules import NatRules
from pytos.securetrack.xml_objects.rest.rules import Rule_Documentation, Record_Set, Bindings_List, \
    Interfaces_List, Cleanup_Set, Rules_List, Network_Objects_List, Policy_Analysis_Query_Result, \
    SecurityPolicyDeviceViolations, Policy_List, Topology_Interfaces_List, Services_List
from pytos.securetrack.xml_objects.rest.security_policy import Security_Policies_List, Security_Policy
from pytos.securetrack.xml_objects.rest.topology import PathCalculationResults
from pytos.securetrack.xml_objects.rest.zones import Zone_List, Zone, Zone_Entry, ZoneDescendantsList


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
        device_by_id = self.helper.get_device_by_id(159)
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
        self.assertEqual(self.helper.get_device_config_by_id(159), b'\x00')

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

    def test_14_get_nat_rules_by_device_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("nats")
        nats = self.helper.get_nat_rules_by_device_id("156")
        self.assertIsInstance(nats, NatRules)


class TestZonesPoliciesAndRevisions(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

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
        dst_tree = lxml.etree.fromstring(zone_obj.to_xml_string())
        dst_b = io.BytesIO()
        dst_tree.getroottree().write_c14n(dst_b)
        self.assertEqual(src_b.getvalue(), dst_b.getvalue())

    @patch('pytos.securetrack.helpers.Secure_Track_Helper.get_zones')
    def test_03_post_security_policy_matrix(self, mock_obj):
        self.mock_get_uri.return_value.headers = {'location': '1'}
        self.mock_get_uri.return_value.status_code = 201
        self.mock_get_uri.return_value.content = fake_request_response("zones")
        mock_obj.return_value = Zone_List.from_xml_string(fake_request_response("zones").decode())
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

    def test_04_post_zone_entry(self):
        self.mock_get_uri.return_value.headers = {'location': '1'}
        self.mock_get_uri.return_value.status_code = 201
        zone_entry = Zone_Entry(1234, "Description", "1.1.1.1", 0, '255.255.255.255', 36)
        entry_id = self.helper.post_zone_entry(zone_entry.zoneId, zone_entry)
        self.assertEqual(entry_id, 1)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            try:
                self.helper.post_zone_entry(zone_entry.zoneId, zone_entry)
            except OSError:
                pass
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securetrack/api/zones/36/entries?context=1',
                auth=('username', 'password'),
                data='<zone_entry>\n  <comment>Description</comment>\n  <id>1234</id>\n  <ip>1.1.1.1</ip>\n  <netmask>255.255.255.255</netmask>\n  <zoneId>36</zoneId>\n</zone_entry>',
                headers={'Content-Type': 'application/xml'},
                files=None
            )

    def test_05_delete_zone_entry(self):
        result = self.helper.delete_zone_entry_by_zone_and_entry_id(1, 1)
        self.assertTrue(result)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            try:
                result = self.helper.delete_zone_entry_by_zone_and_entry_id(1, 1)
            except OSError:
                pass
            mock_post_uri.assert_called_with('DELETE',
                                             'https://localhost/securetrack/api/zones/1/entries/1?context=1',
                                             auth=('username', 'password'),
                                             headers={'Content-Type': 'application/xml'})

    def test_06_modify_zone_entry(self):
        self.mock_get_uri.return_value.content = fake_request_response("zone_entries")
        zone_entries = self.helper.get_entries_for_zone_id(13)
        zone_entry = zone_entries[0]
        zone_entry.comment = "Modified entry"
        zone_entry.ip = '101.101.101.101'
        zone_entry.negate = 0
        zone_entry.netmask = '255.255.255.255'
        result = self.helper.put_zone_entry(13, zone_entry)
        self.assertTrue(result)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            try:
                result = self.helper.put_zone_entry(13, zone_entry)
            except OSError:
                pass
            mock_post_uri.assert_called_with('PUT',
                                             'https://localhost/securetrack/api/zones/13/entries/54?context=1',
                                             auth=('username', 'password'),
                                             data='<zone_entry>\n  <comment>Modified entry</comment>\n  <id>54</id>\n  <ip>101.101.101.101</ip>\n  <negate>0</negate>\n  <netmask>255.255.255.255</netmask>\n  <zoneId>13</zoneId>\n</zone_entry>', headers={'Content-Type': 'application/xml'})

    def test_07_get_zone_by_name(self):
        self.mock_get_uri.return_value.content = fake_request_response("zones")
        zone = self.helper.get_zone_by_name("dmz")
        self.assertIsInstance(zone, Zone)
        self.assertEqual(zone.name, "dmz")

    def test_08_get_device_revisions_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("revisions")
        revisions = self.helper.get_device_revisions_by_id(device_id=155)
        self.assertIsInstance(revisions, Device_Revisions_List)
        self.assertTrue(len(revisions) > 0)

    def test_09_get_policy_analysis(self):
        self.mock_get_uri.return_value.content = fake_request_response("policy_analysis_query_result")
        policy_analysis = self.helper.get_policy_analysis(155)
        self.assertIsInstance(policy_analysis, Policy_Analysis_Query_Result)

    def test_10_get_security_policies(self):
        self.mock_get_uri.return_value.content = fake_request_response("securitypolicylist")
        policies = self.helper.get_security_policies()
        self.assertIsInstance(policies, Security_Policies_List)

    def test_11_get_security_policy_by_name(self):
        self.mock_get_uri.return_value.content = fake_request_response("securitypolicylist")
        policy = self.helper.get_security_policy_by_name("policy")
        self.assertIsInstance(policy, Security_Policy)
        self.assertEqual(policy.name, "policy")

    def test_12_get_security_policy_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("securitypolicylist")
        policy = self.helper.get_security_policy_by_id(3)
        self.assertEqual(policy.id, 3)

    def test_13_delete_security_policy_matrix(self):
        result = self.helper.delete_security_policy_matrix(3)
        self.assertTrue(result)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            try:
                result = self.helper.delete_security_policy_matrix(3)
            except OSError:
                pass
            mock_post_uri.assert_called_with('DELETE',
                                             'https://localhost/securetrack/api/security_policies/3',
                                             auth=('username', 'password'),
                                             headers={'Content-Type': 'application/xml'})

    def test_14_get_revision_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("revision")
        revision = self.helper.get_revision_by_id(5685)
        self.assertIsInstance(revision, Device_Revision)
        self.assertTrue(revision.id, 5685)

    def test_15_get_security_policy_device_violations_by_severity(self):
        self.mock_get_uri.return_value.content = fake_request_response("security_policy_device_violations")
        violations = self.helper.get_security_policy_device_violations_by_severity(159, "CRITICAL", "SECURITY_POLICY")
        self.assertIsInstance(violations, SecurityPolicyDeviceViolations)

    def test_16_get_policies_for_revision(self):
        self.mock_get_uri.return_value.content = fake_request_response("policies")
        policies = self.helper.get_policies_for_revision(1)
        self.assertIsInstance(policies, Policy_List)

    def test_17_post_security_policy_exception(self):
        self.mock_get_uri.return_value.headers = {'location': '1'}
        self.mock_get_uri.return_value.status_code = 201
        xml = fake_request_response("exception")
        policy_exception = security_policy.Security_Policy_Exception.from_xml_string(xml.decode("utf-8"))
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            try:
                self.helper.post_security_policy_exception(policy_exception)
            except OSError:
                pass
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securetrack/api/security_policies/exceptions/?context=1',
                auth=('username', 'password'),
                data=policy_exception.to_xml_string(),
                headers={'Content-Type': 'application/xml'},
                files=None
            )

    def test_18_delete_zone_by_zone_id(self):
        with patch('pytos.common.rest_requests.requests.Request') as mock_delete_uri:
            try:
                self.helper.delete_zone_by_zone_id(1, True)
            except OSError:
                pass
            mock_delete_uri.assert_called_with(
                'DELETE',
                'https://localhost/securetrack/api/zones/1',
                auth=('username', 'password'),
                headers={'Content-Type': 'application/xml'}
            )

    def test_19_get_zone_descendants(self):
        self.mock_get_uri.return_value.content = fake_request_response("zone_descendants")
        zone_descendants_list = self.helper.get_zone_descendants("16")
        self.assertIsInstance(zone_descendants_list, ZoneDescendantsList)

    def test_20_delete_security_policy_exception(self):
        with patch('pytos.common.rest_requests.requests.Request') as mock_delete_uri:
            try:
                self.helper.delete_security_policy_exception(1)
            except OSError:
                pass
            mock_delete_uri.assert_called_with(
                'DELETE',
                'https://localhost/securetrack/api/security_policies/exceptions/1',
                auth=('username', 'password'),
                headers={'Content-Type': 'application/xml'}
            )


class TestTopology(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_topology_interfaces(self):
        self.mock_get_uri.return_value.content = fake_request_response("interfaces")
        topology_interfaces_list = self.helper.get_topology_interfaces(173)
        self.assertIsInstance(topology_interfaces_list, Topology_Interfaces_List)

    def test_02_failed_to_get_topology_interfaces(self):
        self.mock_get_uri.return_value.content = fake_request_response("bad_request_error")
        self.mock_get_uri.return_value.status_code = 400
        with self.assertRaises(REST_Bad_Request_Error):
            self.helper.get_topology_interfaces(173)

    def test_03_get_topology_path(self):
        self.mock_get_uri.return_value.content = fake_request_response("path")
        topology_path = self.helper.get_topology_path(None, None, None)
        self.assertIsInstance(topology_path, PathCalculationResults)


class TestDomains(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_domains(self):
        self.mock_get_uri.return_value.content = fake_request_response("domains")
        domains = self.helper.get_domains()
        self.assertIsInstance(domains, Domains)

    @patch('pytos.securetrack.helpers.Domain.from_xml_string')
    def test_02_get_domain_by_id(self, mock_domain):
        mock_domain.return_value = Domain(1, 'default')
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                self.helper.get_domain_by_id(1)
            except ValueError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/domains/1',
                auth=('username', 'password'),
                headers={},
                params=None
            )


class TestNetworkObjects(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_network_objects_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        network_objects = self.helper.get_network_objects_for_device(158)
        self.assertIsInstance(network_objects, Network_Objects_List)

    def test_02_network_object_text_search(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        network_objects = self.helper.network_object_text_search("192.168", "any_field")
        self.assertIsInstance(network_objects, Network_Objects_List)
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                network_objects = self.helper.network_object_text_search("192.168", "any_field")
            except OSError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/network_objects/search?filter=text&any_field=192.168',
                auth=('username', 'password'),
                headers={},
                params=None
            )

    def test_03_network_object_subnet_search(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                network_objects = self.helper.network_object_subnet_search("192.168.0.0", "contained_in")
            except OSError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/network_objects/search?filter=subnet&contained_in=192.168.0.0',
                auth=('username', 'password'),
                headers={},
                params=None
            )

    # def test_04_get_network_objects(self):
    #     network_objects = self.helper.get_network_objects()
    #     self.assertIsInstance(network_objects, dict)
    #     self.assertTrue(len(network_objects) > 0)
    #
    def test_04_get_network_object_by_device_and_object_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                network_object = self.helper.get_network_object_by_device_and_object_id(158, 3418214)
            except OSError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/devices/158/network_objects/3418214',
                auth=('username', 'password'),
                headers={},
                params=None
            )

    def test_05_get_member_network_objects_for_group_network_object(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        g_network_object = self.helper.get_network_objects_for_device(158)[-1]
        members = self.helper.get_member_network_objects_for_group_network_object(g_network_object, 158)
        self.assertIsInstance(members, list)


class TestServices(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_get_services_for_device(self):
        self.mock_get_uri.return_value.content = fake_request_response("services")
        services = self.helper.get_services_for_device(158)
        self.assertIsInstance(services, Services_List)

    def test_02_get_service_for_device_by_name(self):
        self.mock_get_uri.return_value.content = fake_request_response("services")
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                service = self.helper.get_service_for_device_by_name(158, 'service1')
            except OSError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/devices/158/services?name=service1',
                auth=('username', 'password'),
                headers={},
                params=None
            )

    def test_03_get_service_by_device_and_object_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("services")
        with patch('pytos.common.rest_requests.requests.Request') as mock_get_uri:
            try:
                service = self.helper.get_service_by_device_and_object_id(158, 17973529)
            except OSError:
                pass
            mock_get_uri.assert_called_with(
                'GET',
                'https://localhost/securetrack/api/devices/158/services/17973529',
                auth=('username', 'password'),
                headers={},
                params=None
            )

    def test_04_get_member_services_for_group_service(self):
        self.mock_get_uri.return_value.content = fake_request_response("network_objects")
        g_network_object = self.helper.get_network_objects_for_device(158)[-1]
        self.mock_get_uri.return_value.content = fake_request_response("services")
        members = self.helper.get_member_network_objects_for_group_network_object(g_network_object, 158)
        self.assertIsInstance(members, list)


class TestGeneralSettings(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_Track_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_03_get_change_authorization_status(self):
        self.mock_get_uri.return_value.content = fake_request_response("revisions")
        revisions = self.helper.get_device_revisions_by_id(device_id=158)
        self.assertIsInstance(revisions, Device_Revisions_List)


if __name__ == '__main__':
    unittest.main()
