#!/opt/tufin/securitysuite/ps/python/bin/python3

import argparse
import logging
import os
import shlex
import sys
from pprint import pformat
import json
import multiprocessing
from time import sleep
import threading
from multiprocessing.pool import ThreadPool
import paramiko
from netaddr import IPAddress, AddrFormatError, IPNetwork, IPRange, IPSet
import time
import re


sys.path.append('/opt/tufin/securitysuite/ps/lib')

from Secure_Common.REST_Functions import netmask_to_cidr
from Secure_Track.XML_Objects.REST.Security_Policy import Zone_To_Zone_Security_Requirement, Exception_Exempted_Traffic, \
    Exception_Service_Collection, Security_Policy_Exception, Exception_Custom_Service_Item, \
    Exception_Predefined_Service_Item, Exception_Network_Source_Collection, Exception_Network_Destination_Collection, \
    Exception_Range_Network_Item, Exception_Subnet_Network_Item, Exception_Any_Network_Item, Exception_Zone_Network_Item

# # from Secure_Track.XML_Objects.REST.Rules import Cloud_Network_Object, Host_With_Interfaces_Network_Object, \
# #     Subnet_Network_Object
from Secure_Common.REST_Defines import XML_Tags
# from Secure_Change.XML_Objects.REST import Ticket_Lock, IP_Access_Request_Target_IPV4, IP_Access_Request_Target_IPV6, \
#     IP_Access_Request_Target
from Secure_Track.XML_Objects.REST.Rules import Group_Service, Range_Network_Object, Host_Network_Object, \
    Subnet_Network_Object, Change_Authorization, str_to_bool, Zone
from Secure_Change.XML_Objects.RestApi.Step.AccessRequest.AccessRequest import IP_Access_Request_Target, \
    Any_Access_Request_Target, IP_Range_Access_Request_Target, Object_Access_Request_Target, Access_Request, \
    Protocol_Service_Target, Predefined_Service_Target, Violation_Any_Destination, Violation_Any_Service, \
    Violation_Not_Allowed_Group_Member_service_Object, Violation_Allowed_Group_Member_service_Object, \
    BlockedOnlyCellViolation, RestrictedCellViolation, DNS_Access_Request_Target, IpAddress, \
    Named_Access_Request_Device, Violation_Any_Source, BlockedCellViolation, Any_Service_Target, \
    ApplicationPredefinedServiceTarget, Violation_IP_Range, Violation_IP_Target, Violation_Internet_Source, \
    Violation_Internet_Destination
from Secure_App.XML_Objects.REST import Host_Network_Object as SA_Host_Network_Object, Application, Application_Owner, \
    Customer, Application_Viewer, Application_Editor
from Secure_Common.REST_Requests import POST_Request

from Secure_Common.REST_Functions.Config import Secure_Config_Parser
from Secure_Change.Helpers import Secure_Change_Helper, Secure_Change_API_Handler, Access_Request_Generator
from Secure_Track.Helpers import Secure_Track_Helper
from Secure_App.Helpers import Secure_App_Helper
from Secure_Common.Logging.Logger import setup_loggers
from Secure_Common.Logging.Defines import COMMON_LOGGER_NAME
from Secure_Common.Base_Types import XML_List, Comparable

logger = logging.getLogger(COMMON_LOGGER_NAME)
conf = Secure_Config_Parser()
st_helper = Secure_Track_Helper.from_secure_config_parser(conf)
sc_helper = Secure_Change_Helper.from_secure_config_parser(conf)
sa_helper = Secure_App_Helper.from_secure_config_parser(conf)

IPV4_REGEX = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})(?:/([\d.]+))?')


def get_cli_args():
    parser = argparse.ArgumentParser('')
    parser.add_argument('--debug', action='store_true', help='Print out logging information to STDOUT.')
    # Workaround for SC not passing arguments to the script
    args = parser.parse_args(shlex.split(' '.join(sys.argv[1:])))
    return args


def get_ssh_client(host, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(host, username=username, password=password)
    return ssh_client


def transfer_file_sftp(ssh_client, local_path, remote_path):
    logger.info('Transferring file {} to remote path {}.'.format(local_path, remote_path))
    sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
    sftp_client.put(local_path, remote_path)
    logger.info('Done transferring file {} to remote path {}.'.format(local_path, remote_path))


def get_file_sftp(ssh_client, remote_file_path, local_path):
    if not os.path.exists(local_path):
        try:
            os.makedirs(os.path.dirname(local_path))
        except OSError as ex:
            logger.error(ex)
            sys.exit(1)
    sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
    sftp_client.get(remote_file_path, local_path)


def compare_designer_results_using_difflib():
    ticket = sc_helper.get_ticket_by_id(1356)
    task = ticket.get_step_by_id(7631).get_last_task()
    ar_field = task.get_field_list_by_name('Required Access')[0]
    designer_result_1 = ar_field.get_designer_results(sc_helper.login_data['username'], sc_helper.login_data['password'])

    ticket = sc_helper.get_ticket_by_id(1355)
    task = ticket.get_step_by_index(2).get_last_task()
    ar_field = task.get_field_list_by_name('Required Access')[0]
    designer_result_2 = ar_field.get_designer_results(sc_helper.login_data['username'], sc_helper.login_data['password'])

    import difflib

    print('\n'.join(difflib.unified_diff(a=str(designer_result_1).split('\n'),
                                         b=str(designer_result_2).split('\n'),
                                         lineterm='',
                                         fromfile='Ticket ID {} Step {}'.format(1356, 7631),
                                         tofile='Ticket ID {} Step {}'.format(1355, 'second step'))))


def get_access_requests_objects_as_ips():
    from Secure_Common.REST_Defines import XML_Tags

    object_uids_to_ip_objects_cache = {}

    def ar_object_as_ip_objects(obj):
        """Creates a set of netaddr.IPAddress objects from from obj and returns it

        :param IP_Access_Request_Target | Access_Request_Target obj:
        :rtype: set[netaddr.IPAddress]
        """

        def convert_to_netaddr_object(netaddr_type, *args):
            try:
                return netaddr_type(*args)
            except (AddrFormatError, ValueError) as error:
                logger.debug(error)

        def generate_ip_objects():
            ip_addresses = set()
            if isinstance(obj, Any_Access_Request_Target):
                return
            elif isinstance(obj, Named_Access_Request_Device):
                ip_addresses.add(convert_to_netaddr_object(IPAddress, obj.object_details))
            elif isinstance(obj, IP_Access_Request_Target):
                if obj.netmask == '255.255.255.255':
                    ip_addresses.add(convert_to_netaddr_object(IPAddress, obj.ip_address))
                else:
                    ip_addresses.update(
                        convert_to_netaddr_object(IPNetwork, '{}/{}'.format(obj.ip_address, obj.netmask)))
            elif isinstance(obj, IP_Range_Access_Request_Target):
                ip_addresses.update(convert_to_netaddr_object(IPRange, obj.range_first_ip, obj.range_last_ip))
            elif isinstance(obj, DNS_Access_Request_Target):
                if hasattr(obj, 'ip_address') and obj.ip_address is not None:
                    ip_addresses.add(convert_to_netaddr_object(IPAddress, obj.ip_address))
                elif hasattr(obj, 'dns_ip_addresses'):
                    ip_addresses.add(convert_to_netaddr_object(IPAddress, obj.dns_ip_addresses[0].ip_address))
            elif obj.object_type == 'host':
                ip_addresses.add(convert_to_netaddr_object(IPAddress, obj.object_details.split('/')[0]))
            elif obj.object_type == 'range':
                first_ip, last_ip = IPV4_REGEX.findall(obj.object_details)
                if not isinstance(first_ip, str):
                    first_ip = first_ip[0]
                if not isinstance(last_ip, str):
                    last_ip = last_ip[0]
                ip_addresses.update(convert_to_netaddr_object(IPRange, first_ip, last_ip))
            elif obj.object_type == 'network':
                ip_addresses.update(convert_to_netaddr_object(IPNetwork, obj.object_details))
            elif obj.object_type == 'group':
                st_group_network_objects = st_helper.network_object_text_search(obj.object_name, 'name',
                                                                                exact_match=True)
                # we may still get more than the required, so filtering by UID as well
                try:
                    relevant_group_obj = [group_obj for group_obj in st_group_network_objects
                                          if group_obj.uid == obj.object_UID][0]
                except IndexError:
                    return
                except AttributeError as error:
                    logger.error(error)
                    return
                for member in st_helper.get_member_network_objects_for_group_network_object(relevant_group_obj,
                                                                                            obj.management_id):
                    if isinstance(member, Range_Network_Object):
                        ip_addresses.update(convert_to_netaddr_object(IPRange, member.first_ip, member.last_ip))
                    elif isinstance(member, Host_Network_Object):
                        ip_addresses.add(convert_to_netaddr_object(IPAddress, member.ip))
                    elif isinstance(member, Subnet_Network_Object):
                        ip_addresses.update(
                            convert_to_netaddr_object(IPNetwork, '{}/{}'.format(member.ip, member.netmask)))
                    else:
                        logger.error("Unrecognized type ({}) of member {} in group {}".format(type(member),
                                                                                              member,
                                                                                              relevant_group_obj))
            else:
                logger.error("Unrecognized type of obj: {}".format(type(obj)))
                return
            logger.debug('Calculated {} for {}'.format(ip_addresses, obj))
            try:
                ip_addresses.remove(None)
            except KeyError:  # if None not in ip_addresses
                pass
            return ip_addresses

        logger.debug('Handling {}'.format(obj))
        # if no object_UID we don't have a good key for caching
        if hasattr(obj, 'object_UID'):
            try:
                logger.debug('Trying to get ip objects for {} from cache'.format(obj))
                return object_uids_to_ip_objects_cache[obj.object_UID]
            except KeyError:
                logger.debug('Calculating ip objects for {}'.format(obj))
                object_uids_to_ip_objects_cache[obj.object_UID] = generate_ip_objects()
                return object_uids_to_ip_objects_cache[obj.object_UID]
        else:
            return generate_ip_objects()

    ar_field = sc_helper.get_ticket_by_id(1701).get_current_task().get_field_list_by_type(
        XML_Tags.Attributes.FIELD_TYPE_MULTI_ACCESS_REQUEST)[0]

    for obj in ar_field.access_requests[0].sources.get_contents():
        print(ar_object_as_ip_objects(obj))


def socgen_pbr():
    import re
    from collections import OrderedDict
    from pprint import pprint

    entries = []
    devices_ids = (441,)

    INTERFACES_AND_PBR_NAMES_REGEX = re.compile(r'!\n(interface (?P<interface_name>.*)(?:\n[^!].*)*\nip policy route-map (?P<pbr_name>.*))',
                                                re.MULTILINE)
    ACL_NAMES_AND_ACTIONS_REGEX_TEMPLATE = r'!\n(route-map {pbr_name} permit \d+(?:(?:\n[^!].*)*\nmatch ip address (?P<acl_name>.*))?(?:\n[^!].*)*\n(?P<action>set .*))'

    for device_id in devices_ids:
        device_config = st_helper.get_device_config_by_id(device_id).decode()

        for match in INTERFACES_AND_PBR_NAMES_REGEX.findall(device_config):
            section, interface_name, pbr_name = match

            if interface_name and pbr_name:
                for match in re.findall(ACL_NAMES_AND_ACTIONS_REGEX_TEMPLATE.format(pbr_name=pbr_name), device_config,
                                        re.MULTILINE):
                    section, acl_name, action = match
                    # entry = OrderedDict()
                    # entry['device_id'] = device_id
                    # entry['interface_name'] = interface_name
                    # entry['pbr_name'] = pbr_name
                    # entry['acl_name'] = acl_name
                    # entry['action'] = action
                    # entries.append(entry)

                    entries.append({'device_id': device_id,
                                    'interface_name': interface_name,
                                    'pbr_name': pbr_name,
                                    'acl_name': acl_name,
                                    'action': action})
    return entries


def nsx_prov():

    from utils.nsx_client import NsxClient
    from utils.nsx_objects import Group, Member, IPSet, NsxException

    client = NsxClient('10.100.15.161', 'admin', 'cloud123$')

    def clean():
        try:
            group = client.get_security_group_by_name('non_existing_group')
        except ValueError as error:
            print(error)
        else:
            try:
                client.delete_security_group(group.objectId)
            except Exception as error:
                print(error)
        try:
            client.delete_ip_set(client.get_ip_set_by_name('Net_100.100.100.0_24').objectId)
            client.delete_ip_set(client.get_ip_set_by_name('Host_100.100.100.1').objectId)
        except Exception as error:
            print(error)

    clean()
    # create_group_with_members()

    # group = client.get_security_group_by_name('adi_new_group')
    # print()

    # create_group_with_no_members()

    # new_group = Group(None, 'adi_new_group', [Member(None, 'Host_9.9.9.9')])
    # client.create_new_security_group(new_group)


    # group = client.get_all_security_groups()[0]
    # print()

    # try:
    #     client.create_new_security_group(Group('asafsascdsacasd', None, []))
    # except NsxException as error:
    #     print(error)


def remote_test_example():
    import unittest

    class test(unittest.TestCase):
        def test1(self):
            self.assertTrue(False)

    s = unittest.TestLoader().loadTestsFromTestCase(test)
    unittest.TextTestRunner().run(s)

def main():
    cli_args = get_cli_args()
    setup_loggers(conf.dict('log_levels'), log_to_stdout=cli_args.debug)
    logger.info('Script is called')

    task = sc_helper.get_ticket_by_id(1737).get_last_task()
    sc_helper.reassign_task_by_username(task, 'a', 'a')


if __name__ == '__main__':
    main()
