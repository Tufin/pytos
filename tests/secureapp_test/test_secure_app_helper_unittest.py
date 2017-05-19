#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import os
import sys
import unittest
from unittest.mock import patch

from pytos.secureapp.helpers import Secure_App_Helper
from pytos.secureapp.xml_objects.rest import Application_Owner, Application, Host_Network_Object, \
    Detailed_Application_Connection, User, User_List, Single_Service, Services_List, Applications_List, \
    Network_Objects_List
from pytos.securechange.xml_objects.rest import Group, Service

VALID_TEST_APP_NAME = "TEST_APP_123_321"
VALID_TEST_APP_NAME_AFTER_UPDATE = VALID_TEST_APP_NAME + '_after_update'
VALID_TEST_NETWORK_OBJECT_NAME = "network_object1"
VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE = VALID_TEST_NETWORK_OBJECT_NAME + '_after_update'
VALID_TEST_SERVICE_NAME = "service1"
VALID_TEST_SERVICE_NAME_AFTER_UPDATE = VALID_TEST_SERVICE_NAME + '_after_update'
VALID_TEST_CONNECTION_NAME = "connection1"
VALID_TEST_CONNECTION_NAME_AFTER_UPDATE = VALID_TEST_CONNECTION_NAME + '_after_update'
VALID_TEST_USER_NAME = "adam_123"


def fake_request_response(rest_file):
    full_path = os.path.dirname(os.path.abspath(__file__))
    sub_resources_dir = sys._getframe(1).f_locals['self'].__class__.__name__.lower()
    resource_file = os.path.join(full_path, "resources", sub_resources_dir, "{}.xml".format(rest_file))
    with open(resource_file, mode='rb') as f:
        return f.read()


class Customer(object):
    def __init__(self, id_, name):
        self.id = id_
        self.name = name


class Test_Secure_App_Helper(unittest.TestCase):
    def setUp(self):
        self.user = 'user'
        self.app_name = "test"
        self.helper = Secure_App_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_uri = self.patcher.start()
        self.mock_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_create_app(self):
        self.mock_uri.return_value.headers = {'location': '1'}
        self.mock_uri.return_value.status_code = 201
        app_owner = Application_Owner(None, self.user, self.user, None)
        valid_app = Application(None, VALID_TEST_APP_NAME, "This is the comment for the test app",
                                "false", app_owner, None, None, None, None, None, None)
        app_list = Applications_List([])
        app_list.append(valid_app)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            app_id = self.helper.post_apps(valid_app)
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securechangeworkflow/api/secureapp/repository/applications/',
                auth=('username', 'password'),
                data=app_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertEqual(app_id, 1)

    def test_02_get_app_by_name(self):
        self.mock_uri.return_value.content = fake_request_response("applications")
        app = self.helper.get_app_by_name(self.app_name)
        assert isinstance(app, Application)

    def test_03_failed_get_app_by_id(self):
        self.mock_uri.return_value.status_code = 404
        self.mock_uri.return_value.content = fake_request_response("not_found_error")
        with self.assertRaises(ValueError):
            self.helper.get_app_by_id(1)

    def test_04_update_app(self):
        self.mock_uri.return_value.content = fake_request_response("applications")
        app = self.helper.get_app_by_name(self.app_name)
        app.id = 2
        app.name = VALID_TEST_APP_NAME_AFTER_UPDATE
        app.comment = 'Test app after update.'
        app.decommissioned = 'false'
        app.customer = Customer(99, 'test_customer')
        app_list = Applications_List([])
        app_list.append(app)
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.update_app(app)
            url = "https://localhost/securechangeworkflow/api/secureapp/repository/applications/"
            mock_put_uri.assert_called_with(
                'PUT',
                url,
                auth=('username', 'password'),
                data=app_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )

    def test_05_create_service(self):
        self.mock_uri.return_value.headers = {'location': '1'}
        self.mock_uri.return_value.status_code = 201
        service = Single_Service("service1", "true", None, VALID_TEST_SERVICE_NAME, "tcp_service", 6, 1025,
                                 1025, None, None, "Comment for Service Number One", timeout=1)
        services_list = Services_List([])
        services_list.append(service)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            service_id = self.helper.post_services(service)
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securechangeworkflow/api/secureapp/repository/services/',
                auth=('username', 'password'),
                data=services_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertEqual(service_id, 1)

    def test_06_get_service_by_name(self):
        self.mock_uri.return_value.content = fake_request_response("services")
        service = self.helper.get_service_by_name('AH')
        assert isinstance(service, Single_Service)

    def test_07_update_services(self):
        self.mock_uri.return_value.content = fake_request_response("services")
        service = self.helper.get_service_by_name('AH')
        service.name = VALID_TEST_SERVICE_NAME_AFTER_UPDATE
        service.display_name = VALID_TEST_SERVICE_NAME_AFTER_UPDATE
        service.comment = 'After update'
        service.global_ = 'true'
        service.max = 1026
        service.min = 1024
        service.negate = None
        service.protocol = 6
        services_list = Services_List([])
        services_list.append(service)
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.update_services(service)
            url = "https://localhost/securechangeworkflow/api/secureapp/repository/services/"
            mock_put_uri.assert_called_with(
                'PUT',
                url,
                auth=('username', 'password'),
                data=services_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )

    @patch('pytos.secureapp.helpers.Secure_App_Helper.get_app_by_name')
    def test_08_create_network_object(self, mock_app_obj):
        self.mock_uri.return_value.headers = {'location': '1'}
        self.mock_uri.return_value.status_code = 201
        mock_app_obj.return_value = Applications_List.from_xml_string(fake_request_response("applications").decode())[0]
        network_object = Host_Network_Object("network_object1", "false", None,
                                             VALID_TEST_NETWORK_OBJECT_NAME, "host",
                                             "5.4.3.2")
        network_objects_list = Network_Objects_List([])
        network_objects_list.append(network_object)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            net_obj_id = self.helper.create_network_objects_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE,
                                                                         network_object)
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securechangeworkflow/api/secureapp/repository/applications/15/network_objects',
                auth=('username', 'password'),
                data=network_objects_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertEqual(net_obj_id, 1)
    #
    # def test_08_update_network_object(self):
    #     app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE).id
    #     network_object = self.helper.get_network_object_by_name_for_app_id(VALID_TEST_NETWORK_OBJECT_NAME, app_id)
    #     network_object.name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
    #     network_object.display_name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
    #     self.helper.update_network_objects_for_app_id(app_id, network_object)  # the args are opposite to the other funcs
    #     updated_network = self.helper.get_network_object_by_id_for_app_id(network_object.id, app_id)
    #
    #     network_eval_dict = EvalDict({'id': network_object.id, 'name': network_object.name, 'type': network_object.type,
    #                                   'display_name': network_object.display_name,
    #                                   'is_global()': network_object.is_global(),
    #                                   'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance",
    #                                   'get_attribs()["xsi:type"]': "hostNetworkObjectDTO"})
    #     network_eval_dict.eval_object_attribs(updated_network)
    #     LOGGER.debug(network_eval_dict.get_report())
    #     network_eval_dict.raise_excs_and_fails()
    #
    # # endregion
    #
    #
    # # --------------------------------------------- #
    # # Tests of Detailed_Application_Connection      #
    # # --------------------------------------------- #
    #
    # # region Tests of connection
    #
    # def test_09_create_connection(self):
    #     app_id = self.helper.get_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE).id
    #     network_object = self.helper.get_network_object_by_name_for_app_id(VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE,
    #                                                                   app_id)
    #     service = self.helper.get_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)
    #     connection = Detailed_Application_Connection(None, VALID_TEST_CONNECTION_NAME,
    #                                                                                   None,
    #                                                                                   [network_object], [service],
    #                                                                                   [network_object], "COMMENT", None,
    #                                                                                   None)
    #     connection_id = self.helper.create_connections_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE, connection)
    #     assert connection_id > 0
    #
    #     created_connection = self.helper.get_connection_by_name_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE,
    #                                                                     VALID_TEST_CONNECTION_NAME)
    #
    #     # Assert values within newly created connection.
    #     connection_eval_dict = EvalDict({'id': connection_id, 'name': connection.name, '#external': connection.external,
    #                                      'services[0]': {'id': connection.services[0].id,
    #                                                      'name': connection.services[0].name,
    #                                                      'display_name': connection.services[0].display_name,
    #                                                      'link': {
    #                                                      'get_attribs()["href"]': "https://{}/securechangeworkflow/api/secureapp/repository/services/{}".format(
    #                                                          self.helper.hostname,service.id),
    #                                                      'get_attribs()["xmlns:xsi"]': "http://www.w3.org/2001/XMLSchema-instance"}},
    #                                      'status': 'NOT_COMPLETE'})
    #     connection_eval_dict.eval_object_attribs(created_connection)
    #     LOGGER.debug(connection_eval_dict.get_report())
    #     connection_eval_dict.raise_excs_and_fails()
    #
    # def test_10_update_connection_for_app_id(self):
    #     connection = self.helper.get_connection_by_name_for_app_name(VALID_TEST_APP_NAME_AFTER_UPDATE,
    #                                                             VALID_TEST_CONNECTION_NAME)
    #     connection.name = VALID_TEST_CONNECTION_NAME_AFTER_UPDATE
    #     self.helper.update_connection_for_app_id(connection, app_name=VALID_TEST_APP_NAME_AFTER_UPDATE)
    #
    # # endregion
    #
    # # --------------------------------------------- #
    # # Deletion tests                                #
    # # --------------------------------------------- #
    #
    # # region Deletion tests
    #
    # def test_11_delete_connection_by_id_for_app_id(self):
    #     self.helper.delete_connection_by_id_for_app_id(app_name=VALID_TEST_APP_NAME_AFTER_UPDATE,
    #                                               connection_name=VALID_TEST_CONNECTION_NAME_AFTER_UPDATE)
    #
    # def test_12_delete_service_by_name(self):
    #     self.helper.delete_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)
    #
    # def test_13_delete_app(self):
    #     status = self.helper.delete_app_by_name(VALID_TEST_APP_NAME_AFTER_UPDATE)
    #     assert status
    #
    # # endregion
    #
    #
    # # --------------------------------------------- #
    # # Tests of User                                 #
    # # --------------------------------------------- #
    #
    # # region Tests of user
    #
    # def test_14_create_user(self):
    #     try:
    #         self.helper.delete_user_by_name(VALID_TEST_USER_NAME)
    #     except:
    #         pass
    #     user = User("Adam Delman", None, None, VALID_TEST_USER_NAME, "local",
    #                                                  "1.2.3.4")
    #     user_id = self.helper.create_users(user)
    #     assert user_id > 0
    #
    #     created_user = self.helper.get_user_by_id(user_id)
    #
    #     # because of a bug in the API the display_name is the same as the name
    #     user_eval_dict = EvalDict({'id': user_id, 'display_name': user.name, 'name': user.name,
    #                                'type': 'user', 'ip': '1.2.3.4',
    #                                'get_attribs()["xmlns:xsi"]': user.get_attribs()["xmlns:xsi"]})
    #     user_eval_dict.eval_object_attribs(created_user)
    #     LOGGER.debug(user_eval_dict.get_report())
    #     user_eval_dict.raise_excs_and_fails()
    #
    # def test_15_get_user_list(self):
    #     users_list = self.helper.get_user_list()
    #     assert isinstance(users_list, User_List)
    #     assert len(users_list) > 0
    #
    # def test_16_delete_user(self):
    #     status = self.helper.delete_user_by_name(VALID_TEST_USER_NAME)
    #     assert status
    #
    #     # endregion


if __name__ == '__main__':
    unittest.main()
