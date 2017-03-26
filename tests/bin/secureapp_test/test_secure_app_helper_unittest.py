#!/opt/tufin/securitysuite/ps/python/bin/python3.4

import sys
import unittest

from pytos.common.logging.Logger import setup_loggers
from pytos.secureapp.Helpers import Secure_App_Helper
from pytos.secureapp.XML_Objects.REST import Application_Owner, Application, Host_Network_Object, \
    Detailed_Application_Connection, User, User_List, Single_Service, Services_List
from pytos.securechange.XML_Objects.REST import Group
from pytos.common.functions.Config import Secure_Config_Parser

sys.path.append("ps-dev/tests/bin/eval_tools")
from eval_tools.eval_tools import EvalDict

conf = Secure_Config_Parser()
LOGGER = setup_loggers(conf.dict("log_levels"), PS_LOG_DIR_path="/var/log/ps/tests")

VALID_TEST_APP_NAME = "TEST_APP_123_321"
VALID_TEST_APP_NAME_AFTER_UPDATE = VALID_TEST_APP_NAME + '_after_update'
VALID_TEST_NETWORK_OBJECT_NAME = "network_object1"
VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE = VALID_TEST_NETWORK_OBJECT_NAME + '_after_update'
VALID_TEST_SERVICE_NAME = "service1"
VALID_TEST_SERVICE_NAME_AFTER_UPDATE = VALID_TEST_SERVICE_NAME + '_after_update'
VALID_TEST_CONNECTION_NAME = "connection1"
VALID_TEST_CONNECTION_NAME_AFTER_UPDATE = VALID_TEST_CONNECTION_NAME + '_after_update'
VALID_TEST_USER_NAME = "adam_123"


class Customer(object):
    def __init__(self, id_, name):
        self.id = id_
        self.name = name


class Test_Secure_App_Helper(unittest.TestCase):
    def setUp(self):
        self.helper = Secure_App_Helper.from_secure_config_parser(conf)

    # region Tests of app
    def test_01_create_app(self):
        users_dict = {user.name: user.id for user in self.helper.get_sc_users_list()
                      if user.get_attribs().get('{http://www.w3.org/2001/XMLSchema-instance}type') == "user"}

        user_to_test = [user.name for user in self.helper.get_sc_users_list()
                        if user.name != 'Any User' and not isinstance(user, Group) and len(user.roles) in [5, 6]][0]

        app_owner = Application_Owner(None, user_to_test, user_to_test, None)
        valid_app = Application(None, VALID_TEST_APP_NAME, "This is the comment for the test app",
                                "false", app_owner, None, None, None, None, None, None)
        try:
            self.helper.delete_all_apps()
        except IOError:
            pass

        try:
            customers = self.helper.get_customers()
        except:
            customers = [Customer(99, 'test_customer')]

        valid_app.customer = customers[-1]
        app_id = self.helper.post_apps(valid_app)
        assert app_id > 0

        # Assert the values within the created app.
        app = self.helper.get_app_by_id(app_id)
        assert app.id == app_id

        owner_link = 'https://{}/securechangeworkflow/api/securechange/users/{}'.format(self.helper.hostname, users_dict[valid_app.owner.name])
        app_eval_dict = EvalDict(
            {'name': valid_app.name, 'comment': valid_app.comment, 'decommissioned': valid_app.decommissioned,
             'owner': {'id': users_dict[valid_app.owner.name], 'name': valid_app.owner.name,
                       'link': {'get_attribs()["href"]': owner_link,
                                'get_attribs()["xmlns:xsi"]': 'http://www.w3.org/2001/XMLSchema-instance'}},
             'customer': {'id': valid_app.customer.id, 'name': valid_app.customer.name},
             'status': 'NOT_APPLICABLE', '!created': None})
        app.customer = customers[-1]
        app_eval_dict.eval_object_attribs(app)
        LOGGER.debug(app_eval_dict.get_report())

        app_eval_dict.raise_excs_and_fails()

        empty_fields = ('editors', 'modified', 'open_tickets')
        for empty_field in empty_fields:
            assert not getattr(app, empty_field)

    def test_02_get_app(self):
        helper = Secure_App_Helper.from_secure_config_parser(conf)
        first_app = self.helper.get_app_by_name(VALID_TEST_APP_NAME)
        assert isinstance(first_app, Application)
        second_app = self.helper.get_app_by_id(first_app.id)
        assert first_app.to_xml_string() == second_app.to_xml_string()
        try:
            app = self.helper.get_app_by_name("APP_DOES_NOT_EXIST")
        except ValueError as app_exception:
            assert isinstance(app_exception, ValueError)

    def test_03_update_app(self):
        users_dict = {user.name: user.id for user in self.helper.get_sc_users_list() if
              user.get_attribs().get('{http://www.w3.org/2001/XMLSchema-instance}type') == "user"}

        user_to_test = [user.name for user in self.helper.get_sc_users_list()
                        if user.name != 'Any User' and not isinstance(user, Group) and len(user.roles) in [5, 6]][0]
        app_owner = Application_Owner(None, user_to_test, user_to_test, None)
        valid_app = Application(None, VALID_TEST_APP_NAME,
                                                                 "This is the comment for the test app",
                                                   "false", app_owner, None, None, None, None, None, None)
        app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME).id
        updated_app = valid_app
        try:
            customers = self.helper.get_customers()
        except:
            customers = [Customer(99, 'test_customer')]
        updated_app.id = app_id
        updated_app.name = VALID_TEST_APP_NAME_AFTER_UPDATE
        updated_app.comment = 'Test app after update.'
        updated_app.decommissioned = 'false'
        updated_app.customer = customers[0]
        self.helper.update_app(updated_app)
        result_app = self.helper.get_app_by_id(app_id)

        # Assert values within updated application.
        owner_link = 'https://{}/securechangeworkflow/api/securechange/users/{}'.format(self.helper.hostname,users_dict[updated_app.owner.name])
        updated_app_eval_dict = EvalDict(
            {'id': updated_app.id, 'name': updated_app.name, 'comment': updated_app.comment,
             'decommissioned': updated_app.decommissioned,
             'owner': {'id': users_dict[updated_app.owner.name], 'name': updated_app.owner.name,
                       'link': {'get_attribs()["href"]': owner_link,
                                'get_attribs()["xmlns:xsi"]': 'http://www.w3.org/2001/XMLSchema-instance'}},
             'customer': {'id': updated_app.customer.id, 'name': updated_app.customer.name},
             'status': 'NOT_APPLICABLE', '!modified': None})
        result_app.customer = customers[0]
        updated_app_eval_dict.eval_object_attribs(result_app)
        LOGGER.debug(updated_app_eval_dict.get_report())
        updated_app_eval_dict.raise_excs_and_fails()

    # endregion


    # --------------------------------------------- #
    # Tests of Single_service                       #
    # --------------------------------------------- #

    # region Tests of service

    def test_04_create_service(self):  # display_name and is_global are being ignored.
        # service = secureapp.XML_Objects.REST.Single_Service("Service Number One", "false", None,
        service = Single_Service("service1", "true", None,
                                                                  VALID_TEST_SERVICE_NAME, "tcp_service", 6, 1025,
                                                                  1025, None, None, "Comment for Service Number One",
                                                                  timeout=1)
        try:
            self.helper.delete_service_by_name(VALID_TEST_SERVICE_NAME)
        except:
            pass
        try:
            self.helper.delete_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)
        except:
            pass

        service_id = self.helper.post_services(service)
        assert service_id > 0

        created_service = self.helper.get_service_by_name(VALID_TEST_SERVICE_NAME)

        # Asserting values within newly created service.
        service_eval_dict = EvalDict({'id': service_id, 'name': service.name, 'type': service.type,
                                      'display_name': service.display_name, 'is_global()': service.is_global(),
                                      'protocol': service.protocol, 'min': service.min, 'max': service.max,
                                      'negate': service.negate, 'uid': service.uid, 'comment': service.comment,
                                      'application_id': service.application_id,
                                      'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance",
                                      'get_attribs()["xsi:type"]': "singleServiceDTO"})

        service_eval_dict.eval_object_attribs(created_service)
        LOGGER.debug(service_eval_dict.get_report())
        service_eval_dict.raise_excs_and_fails()

    def test_05_update_services(self):
        service = self.helper.get_service_by_name(VALID_TEST_SERVICE_NAME)
        service.name = VALID_TEST_SERVICE_NAME_AFTER_UPDATE
        service.display_name = VALID_TEST_SERVICE_NAME_AFTER_UPDATE
        service.comment = 'After update'
        service.global_ = 'true'
        service.max = 1026
        service.min = 1024
        service.negate = None
        service.protocol = 6
        self.helper.update_services(service)
        updated_service = self.helper.get_service_by_name(service.name)



        updated_service_eval_dict = EvalDict({'id': service.id, 'name': service.name, 'type': service.type,
                                              'display_name': service.display_name, 'is_global()': service.is_global(),
                                              'protocol': service.protocol, 'min': service.min, 'max': service.max,
                                              'negate': service.negate, 'uid': service.uid, 'comment': service.comment,
                                              'application_id': service.application_id,
                                              'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance",
                                              'get_attribs()["xsi:type"]': "singleServiceDTO"})
        updated_service_eval_dict.eval_object_attribs(updated_service)
        LOGGER.debug(updated_service_eval_dict.get_report())
        updated_service_eval_dict.raise_excs_and_fails()

    def test_06_get_service_list(self):
        services_list = self.helper.get_all_services()
        assert isinstance(services_list, Services_List)
        assert len(services_list) > 0

    # endregion


    # --------------------------------------------- #
    # Tests of Host_Network_Object                  #
    # --------------------------------------------- #

    # region Tests of network

    def test_07_create_network_object(self):
        network_object = Host_Network_Object("network_object1", "false", None,
                                             VALID_TEST_NETWORK_OBJECT_NAME, "host",
                                             "5.4.3.2")
        net_obj_id = self.helper.create_network_objects_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE, network_object)
        assert net_obj_id > 0

        app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE).id
        created_network = self.helper.get_network_object_by_id_for_app_id(net_obj_id, app_id)

        # Assert values within created network.
        network_eval_dict = EvalDict({'id': net_obj_id, 'name': network_object.name, 'type': network_object.type,
                                      'display_name': network_object.display_name,
                                      'is_global()': network_object.is_global(),
                                      'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance",
                                      'get_attribs()["xsi:type"]': "hostNetworkObjectDTO"})
        network_eval_dict.eval_object_attribs(created_network)
        LOGGER.debug(network_eval_dict.get_report())
        network_eval_dict.raise_excs_and_fails()

    def test_08_update_network_object(self):
        app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE).id
        network_object = self.helper.get_network_object_by_name_for_app_id(VALID_TEST_NETWORK_OBJECT_NAME, app_id)
        network_object.name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
        network_object.display_name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
        self.helper.update_network_objects_for_app_id(app_id, network_object)  # the args are opposite to the other funcs
        updated_network = self.helper.get_network_object_by_id_for_app_id(network_object.id, app_id)

        network_eval_dict = EvalDict({'id': network_object.id, 'name': network_object.name, 'type': network_object.type,
                                      'display_name': network_object.display_name,
                                      'is_global()': network_object.is_global(),
                                      'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance",
                                      'get_attribs()["xsi:type"]': "hostNetworkObjectDTO"})
        network_eval_dict.eval_object_attribs(updated_network)
        LOGGER.debug(network_eval_dict.get_report())
        network_eval_dict.raise_excs_and_fails()

    # endregion


    # --------------------------------------------- #
    # Tests of Detailed_Application_Connection      #
    # --------------------------------------------- #

    # region Tests of connection

    def test_09_create_connection(self):
        app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE).id
        network_object = self.helper.get_network_object_by_name_for_app_id(VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE,
                                                                      app_id)
        service = self.helper.get_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)
        connection = Detailed_Application_Connection(None, VALID_TEST_CONNECTION_NAME,
                                                                                      None,
                                                                                      [network_object], [service],
                                                                                      [network_object], "COMMENT", None,
                                                                                      None)
        connection_id = self.helper.create_connections_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE, connection)
        assert connection_id > 0

        created_connection = self.helper.get_connection_by_name_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE,
                                                                        VALID_TEST_CONNECTION_NAME)

        # Assert values within newly created connection.
        connection_eval_dict = EvalDict({'id': connection_id, 'name': connection.name, '#external': connection.external,
                                         'services[0]': {'id': connection.services[0].id,
                                                         'name': connection.services[0].name,
                                                         'display_name': connection.services[0].display_name,
                                                         'link': {
                                                         'get_attribs()["href"]': "https://{}/securechangeworkflow/api/secureapp/repository/services/{}".format(
                                                             self.helper.hostname,service.id),
                                                         'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance"}},
                                         'status': 'NOT_COMPLETE'})
        connection_eval_dict.eval_object_attribs(created_connection)
        LOGGER.debug(connection_eval_dict.get_report())
        connection_eval_dict.raise_excs_and_fails()

    def test_10_update_connection_for_app_id(self):
        connection = self.helper.get_connection_by_name_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE,
                                                                VALID_TEST_CONNECTION_NAME)
        connection.name = VALID_TEST_CONNECTION_NAME_AFTER_UPDATE
        self.helper.update_connection_for_app_id(connection, app_name=VALID_TEST_APP_NAME_AFTER_UPDATE)

    # endregion

    # --------------------------------------------- #
    # Deletion tests                                #
    # --------------------------------------------- #

    # region Deletion tests

    def test_11_delete_connection_by_id_for_app_id(self):
        self.helper.delete_connection_by_id_for_app_id(app_name=VALID_TEST_APP_NAME_AFTER_UPDATE,
                                                  connection_name=VALID_TEST_CONNECTION_NAME_AFTER_UPDATE)

    def test_12_delete_service_by_name(self):
        self.helper.delete_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)

    def test_13_delete_app(self):
        status = self.helper.delete_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE)
        assert status

    # endregion


    # --------------------------------------------- #
    # Tests of User                                 #
    # --------------------------------------------- #

    # region Tests of user

    def test_14_create_user(self):
        try:
            self.helper.delete_user_by_name(VALID_TEST_USER_NAME)
        except:
            pass
        user = User("Adam Delman", None, None, VALID_TEST_USER_NAME, "local",
                                                     "1.2.3.4")
        user_id = self.helper.create_users(user)
        assert user_id > 0

        created_user = self.helper.get_user_by_id(user_id)

        # because of a bug in the API the display_name is the same as the name
        user_eval_dict = EvalDict({'id': user_id, 'display_name': user.name, 'name': user.name,
                                   'type': 'user', 'ip': '1.2.3.4',
                                   'get_attribs()["xmlns:xsi"]': user.get_attribs()["xmlns:xsi"]})
        user_eval_dict.eval_object_attribs(created_user)
        LOGGER.debug(user_eval_dict.get_report())
        user_eval_dict.raise_excs_and_fails()

    def test_15_get_user_list(self):
        users_list = self.helper.get_user_list()
        assert isinstance(users_list, User_List)
        assert len(users_list) > 0

    def test_16_delete_user(self):
        status = self.helper.delete_user_by_name(VALID_TEST_USER_NAME)
        assert status

        # endregion


if __name__ == '__main__':
    unittest.main()
