#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import os
import sys
import unittest
from unittest.mock import patch

from pytos.secureapp.helpers import Secure_App_Helper
from pytos.secureapp.xml_objects.base_types import Network_Object
from pytos.secureapp.xml_objects.rest import Application_Owner, Application, Host_Network_Object, \
    Detailed_Application_Connection, User, User_List, Single_Service, Services_List, Applications_List, \
    Network_Objects_List, Connection_List
from pytos.securechange.xml_objects.rest import Group, Service

VALID_TEST_APP_NAME = "TEST_APP_123_321"
VALID_TEST_APP_NAME_AFTER_UPDATE = VALID_TEST_APP_NAME + '_after_update'
VALID_TEST_NETWORK_OBJECT_NAME = "network_object1"
VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE = VALID_TEST_NETWORK_OBJECT_NAME + '_after_update'
VALID_TEST_SERVICE_NAME = "service1"
VALID_TEST_SERVICE_NAME_AFTER_UPDATE = VALID_TEST_SERVICE_NAME + '_after_update'
VALID_TEST_CONNECTION_NAME = "Connection 1"
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
        self.app_id = 15
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
        network_object = Host_Network_Object("network_object1", "false", None, VALID_TEST_NETWORK_OBJECT_NAME,
                                             "host", "5.4.3.2")
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

    def test_09_get_network_object_by_id_for_app_id(self):
        self.mock_uri.return_value.content = fake_request_response("network_objects")
        network_object = self.helper.get_network_object_by_id_for_app_id(286, self.app_id)
        self.assertIsInstance(network_object, Network_Object)

    def test_10_update_network_object(self):
        self.mock_uri.return_value.content = fake_request_response("network_objects")
        network_object = self.helper.get_network_object_by_id_for_app_id(286, self.app_id)
        network_object.name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
        network_object.display_name = VALID_TEST_NETWORK_OBJECT_NAME_AFTER_UPDATE
        network_objects_list = Network_Objects_List([])
        network_objects_list.append(network_object)
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            result = self.helper.update_network_objects_for_app_id(self.app_id, network_object)
            url = "https://localhost/securechangeworkflow/api/secureapp/repository/applications/15/network_objects"
            mock_put_uri.assert_called_with(
                'PUT',
                url,
                auth=('username', 'password'),
                data=network_objects_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertTrue(result)

    @patch('pytos.secureapp.helpers.Secure_App_Helper.get_app_by_name')
    def test_11_create_connection(self, mock_app_obj):
        mock_app_obj.return_value = Applications_List.from_xml_string(fake_request_response("applications").decode())[0]
        self.mock_uri.return_value.content = fake_request_response("network_objects")
        network_object = self.helper.get_network_object_by_id_for_app_id(286, self.app_id)
        self.mock_uri.return_value.content = fake_request_response("services")
        service = self.helper.get_service_by_name('AH')
        connection = Detailed_Application_Connection(None, VALID_TEST_CONNECTION_NAME, None, [network_object],
                                                     [service], [network_object], "COMMENT", None, None)
        connection_list = Connection_List([])
        connection_list.append(connection)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            self.mock_uri.return_value.headers = {'location': '1'}
            self.mock_uri.return_value.status_code = 201
            connection_id = self.helper.create_connections_for_app_name(self.app_name, connection)
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securechangeworkflow/api/secureapp/repository/applications/15/connections',
                auth=('username', 'password'),
                data=connection_list.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertEqual(connection_id, 1)

    def test_12_get_connection_by_name_for_app_id(self):
        self.mock_uri.return_value.content = fake_request_response("connections")
        connection = self.helper.get_connection_by_name_for_app_id(self.app_id, VALID_TEST_CONNECTION_NAME)
        self.assertIsInstance(connection, Detailed_Application_Connection)

    def test_13_update_connection_for_app_id(self):
        self.mock_uri.return_value.content = fake_request_response("connections")
        connection = self.helper.get_connection_by_name_for_app_id(self.app_id, VALID_TEST_CONNECTION_NAME)
        connection.name = VALID_TEST_CONNECTION_NAME_AFTER_UPDATE
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.update_connection_for_app_id(connection, app_id=self.app_id)
            url = "https://localhost/securechangeworkflow/api/secureapp/repository/applications/15/connections/31"
            mock_put_uri.assert_called_with(
                'PUT',
                url,
                auth=('username', 'password'),
                data=connection.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )

    def test_14_delete_connection_by_id_for_app_id(self):
        with patch('pytos.common.rest_requests.requests.Request') as mock_delete_uri:
            self.helper.delete_connection_by_id_for_app_id(app_id=self.app_id, connection_id=31)
            mock_delete_uri.assert_called_with(
                'DELETE',
                'https://localhost/securechangeworkflow/api/secureapp/repository/applications/15/connections/31',
                auth=('username', 'password'),
                headers={'Content-Type': 'application/xml'}
            )

    def test_15_delete_service_by_name(self):
        with patch('pytos.common.rest_requests.requests.Request') as mock_delete_uri:
            result = self.helper.delete_service_by_name(VALID_TEST_SERVICE_NAME_AFTER_UPDATE)
            mock_delete_uri.assert_called_with(
                'DELETE',
                'https://localhost/securechangeworkflow/api/secureapp/repository/services?name={}'.format(VALID_TEST_SERVICE_NAME_AFTER_UPDATE),
                auth=('username', 'password'),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertTrue(result)

    def test_13_delete_app_by_id(self):
        self.mock_uri.return_value.content = fake_request_response("applications")
        app = self.helper.get_app_by_name(self.app_name)
        with patch('pytos.common.rest_requests.requests.Request') as mock_delete_uri:
            result = self.helper.delete_app_by_id(app.id)
            mock_delete_uri.assert_called_with(
                'DELETE',
                'https://localhost/securechangeworkflow/api/secureapp/applications/{}'.format(app.id),
                auth=('username', 'password'),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertTrue(result)
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
