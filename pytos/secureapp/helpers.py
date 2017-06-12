
import logging

from requests.exceptions import RequestException

from pytos.common.definitions.Url_Params_Builder import URLParamBuilderDict
from pytos.common.exceptions import REST_Not_Found_Error, REST_Client_Error, REST_Unauthorized_Error, \
    REST_Bad_Request_Error
from pytos.common.logging.definitions import HELPERS_LOGGER_NAME
from pytos.secureapp.xml_objects.rest import Connection_List, User_List, Applications_List, Services_List, Customers_List, \
    Network_Objects_List, Application, User, Single_Service, Group_Service, Basic_Network_Object,\
    Range_Network_Object, Host_Network_Object, Subnet_Network_Object, Group_Network_Object, \
    Detailed_Application_Connection, Customer, Connections_To_Applications, Connection_To_Application,\
    Application_Interfaces, Connection_To_Application_Packs, Detailed_Connection_To_Application_Pack, \
    ConnectionExtendedList, VM_Instances
from pytos.securechange.helpers import Secure_Change_Helper

logger = logging.getLogger(HELPERS_LOGGER_NAME)


class Secure_App_Helper(Secure_Change_Helper):
    """
    This class is used to interact via HTTP with SecureApp.
    It also allows for easy sending of email messages and writing to the SecureChange Message Board.
    """

    def __init__(self, hostname, login_data, **kwargs):
        """
        :param hostname: The SecureApp hostname with which we will communicate via HTTP.
        :type hostname: str
        :param login_data: A tuple of (username,password) used for basic authentication with the specified hostname.
        :type login_data: tuple
        :param message_board_enabled: (Optional) If set to False, Message Board functionality will be disabled.
        :type message_board_enabled: bool
        """
        logger.debug("Setting up SecureApp Helper.")
        self._app_list = Applications_List([])
        self._service_list = Services_List([])
        self._user_list = User_List([])
        self._customers_list = Customers_List([])
        super().__init__(hostname, login_data, **kwargs)

    def get_user_list(self):
        """
        Get the list of currently configured SecureApp users.
        :return: The list of currently configured SecureApp users.
        :rtype:User_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp users list.")
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository/users",
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET SecureApp users list"
            logger.critical(message)
            raise IOError(message)
        self._user_list = User_List.from_xml_string(response_string)
        return self._user_list

    def get_user_by_id(self, user_id):
        """
        Get the SecureApp user whose ID matches the specified ID.
        :param user_id: The ID for the user which will be returned.
        :type user_id: int
        :return: The user whose ID matches the specified ID.
        :rtype:User
        :raise ValueError: If an user with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp users with ID '%s'.", user_id)
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository/users/{}".format(user_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "User with ID '{}' does not exist.".format(user_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp users list."
            logger.critical(message)
            raise IOError(message)
        return User.from_xml_string(response_string)

    def get_user_by_name(self, user_name):
        """
        Get the SecureApp user whose name matches the specified name.
        :param user_name: The name for the user which will be returned.
        :type user_name: name
        :return: The user whose name matches the specified name.
        :rtype:User
        :raise ValueError: If an user with the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp user with name '%s'.", user_name)
        self.get_user_list()
        for user in self._user_list:
            if user.name == user_name:
                return user
        message = "An user with the name '{}' does not exist.".format(user_name)
        logger.critical(message)
        raise ValueError(message)

    def get_app_by_name(self, app_name, app_domain=None):
        """
        Get the SecureApp application whose name matches the specified name.
        :param app_name: The name of the application to be returned.
        :type app_name: str
        :param app_domain: The domain where app resides
        :type app_domain: str
        :return: The application whose name matches the specified name.
        :rtype:Application
        :raise ValueError: If an application with the specified name is not found.
        """

        if app_domain:
            log_msg = "Getting SecureApp application with name '{}' and domain name '{}'.".format(app_name, app_domain)
        else:
            log_msg = "Getting SecureApp application with name '{}'.".format(app_name)
        logger.info(log_msg)
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository/applications?name={}".format(app_name),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET SecureApp application list"
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "An application with the name '{}' does not exist.".format(app_name)
            logger.critical(message)
            raise ValueError(message)

        found_apps = Applications_List.from_xml_string(response_string)
        try:
            if app_domain:
                try:
                    return [app for app in found_apps if app.customer.name.lower() == app_domain.lower()][0]
                except (KeyError, AttributeError):
                    logger.info("No domain found, assuming single domain mode")
                    return found_apps[0]

            else:
                return found_apps[0]
        except IndexError:
            message = "An application with the name '{}' does not exist.".format(app_name)
            logger.critical(message)
            raise ValueError(message)

    def get_app_by_id(self, app_id):
        """
        Get the SecureApp application whose ID matches the specified ID.
        :param app_id: The ID of the application to be returned.
        :type app_id: int|str
        :return: The application whose ID matches the specified ID.
        :rtype:Application
        :raise ValueError: If an application with the specified ID is not found.
        """
        logger.info("Getting SecureApp application with ID '%s'.", app_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}".format(app_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Application with ID {} does nto exist".format(app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp with ID".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Application.from_xml_string(response_string)

    def get_application_list(self):
        """
        Get the list of currently configured SecureApp applications.
        :return: The currently configured SecureApp applications list.
        :rtype:Applications_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp applications list.")
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository/applications",
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET SecureApp application list"
            logger.critical(message)
            raise IOError(message)
        self._app_list = Applications_List.from_xml_string(response_string)
        return self._app_list

    def get_application_list_by_user_permissions(self, owner=True, editor=True, user_id=None):
        """
        Get the list of currently configured SecureApp applications.
        :param owner: Applications where user is owner
        :type owner: bool
        :param editor: Applications where user is editor
        :type editor: bool
        :param user_id: The user ID who has permissions. If not user for API would be used for filter
        :type user_id: str|int
        :return: The currently configured SecureApp applications list.
        :rtype:Applications_List
        :raise IOError: If there was a communication error.
        """
        if not user_id:
            log_user_id = "used for API call"
        else:
            log_user_id = user_id
        logger.info("Getting SecureApp applications list where user {} is owner({}) and editor({}).".format(
            log_user_id, owner, editor
        ))
        filter_params = []
        if owner:
            filter_params.append("app_owner")
        if editor:
            filter_params.append("app_editor")
        if filter_params:
            params = ",".join(filter_params)
            query_filter = "?app_permissions={}".format(params)
            if user_id:
                query_filter += "&userId={}".format(user_id)
        else:
            query_filter = ""
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository/applications{}".format(
                query_filter), expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET SecureApp application list"
            logger.critical(message)
            raise IOError(message)
        return Applications_List.from_xml_string(response_string)

    def get_services_list(self, param_builder=None):
        """
        Get the list of currently configured SecureApp services.
        :param param_builder: Filter parameters
        :type param_builder: URLParamBuilderInterface
        :return: The currently configured SecureApp services list.
        :rtype:Services_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp services list")
        url = "/securechangeworkflow/api/secureapp/repository/services"

        if param_builder:
            url = "{}{}".format(url, param_builder.build())
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            raise IOError("Failed to GET SecureApp services list.")
        return Services_List.from_xml_string(response_string)

    def get_all_services(self, global_service_only=False):
        """
        Get the list of currently configured SecureApp services.
        :param global_service_only: Retrieve global services
        :return: The currently configured SecureApp services list.
        :rtype:Services_List
        :raise IOError: If there was a communication error.
        """
        if global_service_only:
            param_dict = {'globals_only': True}
        else:
            param_dict = {}
        param_builder = URLParamBuilderDict(param_dict)
        self._service_list = self.get_services_list(param_builder)
        return self._service_list

    def get_service_list_available_for_app(self, app_id=None, app_name=None, include_global=False):
        """
        Get the list of services that are available to be used in specific application:
        services created locally in this application and services created globally for all applications
        :param app_id: ID of an application
        :type app_id: int
        :param app_name: Name of the application
        :type app_name: str
        :param include_global: If to include or not global services
        :type include_global: bool
        :raise ValueError: If wrong parameters are used
        :raise IOError: If there was problem in communication or API request
        :return: The list of services
        :rtype:Services_List
        """
        if not app_id and not app_name:
            msg = "Can't get the list of available services for" \
                  " application as no ID or name of application is provided"
            logger.critical(msg)
            raise ValueError(msg)
        if not app_id:
            app_id = self.get_app_by_name(app_name).id
        logger.info("Getting all services available for application with ID %s", app_id)
        all_services = self.get_all_services()
        return [service for service in all_services
                if (service.application_id is not None and service.application_id == app_id)
                or (service.is_global() and include_global)]

    def search_services_available_for_app(self, service_id=None, service_name=None,
                                          app_id=None, app_name=None, include_global=False):
        """
        Find services available for application with specified name or ID
        :param service_name: The name of the service
        :param service_id: The ID of the service
        :param app_id: The ID of the application
        :param app_name: The name of the application
        :param include_global: If to include global services in search
        :return: the list of services found with given id or name
        """
        if not any((service_id, service_name)):
            msg = "No service name or ID provided."
            logger.critical(msg)
            raise ValueError(msg)
        if not app_id and not app_name:
            msg = "No application name or ID provided."
            logger.critical(msg)
            raise ValueError(msg)
        if not app_id:
            app_id = self.get_app_by_name(app_name).id
        if service_name:
            service_info = "with name '{}'".format(service_name)
        else:
            service_info = "with ID {}".format(service_id)
        logger.info("Searching for services {} for application with ID {}".format(service_info, app_id))
        available_services = self.get_service_list_available_for_app(app_id, app_name, include_global)

        if service_name:
            return [service for service in available_services
                    if (service_name.lower() == service.name.lower())]
        else:
            return [service for service in available_services
                    if service.id == service_id]

    def get_service_by_id(self, service_id):
        """
        Get the SecureApp service by ID
        :param service_id: The ID of the service to be returned.
        :type service_id: str|int
        :return: The service whose name matches the specified name.
        :rtype:Single_Service|Group_Service
        :raise ValueError: If a service with the specified name is not found.
        """
        logger.debug("Getting SecureApp service with ID '%s'.", service_id)

        # As object does not have attribute, this API will crash. Uncomment when fixed

        # try:
        #     response_string = self.get_uri(
        #         "/securechangeworkflow/api/secureapp/repository/services/{}".format(service_id),
        #         expected_status_codes=200).response.content
        # except REST_Not_Found_Error:
        #     message = "Service with ID {} does not exist.".format(service_id)
        #     logger.critical(message)
        #     raise ValueError(message)
        # except RequestException:
        #     message = "Failed to get SecureApp service with ID {}.".format(service_id)
        #     logger.critical(message)
        #     raise IOError(message)
        # return Service_Object.from_xml_string_auto_type(response_string)
        try:
            return [service for service in self.get_all_services() if str(service.id) == str(service_id)][0]
        except IndexError:
            message = "Service with ID {} does not exist.".format(service_id)
            logger.critical(message)
            raise ValueError(message)

    def get_service_by_name(self, service_name, param_builder=None):
        """
        Get the SecureApp service whose name matches the specified name.
        :param service_name: The name of the service to be returned.
        :type service_name: str
        :param param_builder: The URI parameters builder
        :type param_builder: T <= pytos.common.API_Defines.Url_Params_Builder.URLParamBuilderInterface
        :return: The service whose name matches the specified name.
        :rtype:Single_Service|Group_Service
        :raise ValueError: If a service with the specified name is not found.
        """
        logger.debug("Getting SecureApp service with name '%s'.", service_name)
        if not param_builder:
            param_builder = URLParamBuilderDict({'name': service_name})
        else:
            param_builder.set("name", service_name)
        try:
            return self.get_services_list(param_builder)[0]
        except (IndexError, REST_Not_Found_Error):
            message = "A service with the name '{}' does not exist.".format(service_name)
            logger.critical(message)
            raise ValueError(message)

    def get_service_list_for_app_id(self, app_id):
        """
        Get the list of services for Application by Application ID
        :param app_id: The ID of Application in SecureApp to get services
        :type app_id: int
        :return: The list of services configured for Application
        :rtype:Services_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp service list for application with ID %s", app_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/services".format(app_id),
                expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get SecureApp services list for application with ID {}".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Services_List.from_xml_string(response_string)

    def get_service_list_for_app_name(self, app_name):
        """
        Get the list of services for Application by Application name
        :param app_name: The Name of the application for provide services list for
        :type app_name: str
        :return: The list of services configured for Application
        :rtype:Services_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp services list for application '%s'", app_name)
        app_id = self.get_app_by_name(app_name).id
        return self.get_service_list_for_app_id(app_id)

    def get_connections_list_for_app_id(self, app_id):
        """
        Get the SecureApp connections list for the application whose ID matches the specified ID.
        :param app_id: The ID of the application whose connections will be returned.
        :type app_id: int
        :return: The connections list for the application whose ID matches the specified ID.
        :rtype:Connection_List
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp connections list for application with ID '%s'.", app_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections".format(app_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Application with ID {0} does not exist.".format(app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get SecureApp connections list for application with ID {}.".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Connection_List.from_xml_string(response_string)

    def get_extended_connections_list_for_app_id(self, app_id):
        """
        Get extended connections (with all information)
        :return:
        """
        logger.info("Getting SecureApp connections with details for application with ID {}".format(app_id))
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections_extended".format(app_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            msg = "Application with ID does not exists".format(app_id)
            logger.critical(msg)
            raise ValueError(msg)
        except RequestException:
            msg = "Failed to get SecureApp connections list for application with ID {}".format(app_id)
            logger.critical(msg)
            raise IOError(msg)
        return ConnectionExtendedList.from_xml_string(response_string)

    def get_connections_list_for_app_name(self, app_name):
        """
        Get the SecureApp connection list for the application whose name matches the specified name.
        :param app_name: The name of the application whose connection list will be returned.
        :type app_name: str
        :return: The connections list for the application whose name matches the specified name.
        :rtype:Connection_List
        :raise ValueError: If an application with the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp connections list for application with name '%s'.", app_name)
        app_id = self.get_app_by_name(app_name).id
        return self.get_connections_list_for_app_id(app_id)

    def get_connection_by_name_for_app_id(self, app_id, connection_name):
        """
        Get the SecureApp connection by name for application with specified ID
        :param app_id: The ID of application to search connection from
        :type app_id: int
        :param connection_name: The name of the connection to be returned.
        :type connection_name: str
        :return: The connection whose name matches the specified name
        :rtype:Detailed_Application_Connection
        :raise ValueError: If connection with the specified ID is not found.
        """
        logger.debug("Getting SecureApp Connection with name '%s' "
                     "from application with ID %s.", connection_name, app_id)
        connection_list = self.get_connections_list_for_app_id(app_id)
        for connection in connection_list:
            if connection.name.lower() == connection_name.lower():
                return connection
        message = "A connection with the name '{}' does not exist in application with ID {}.".format(
            connection_name,
            app_id)
        logger.critical(message)
        raise ValueError(message)

    def get_connection_by_name_for_app_name(self, app_name, connection_name):
        """
        Get the SecureApp connection by name for application with specified ID
        :param app_name: The name of application to search connection from
        :type app_name: str
        :param connection_name: The name of the connection to be returned.
        :type connection_name: str
        :return: The connection whose name matches the specified name
        :rtype:Detailed_Application_Connection
        :raise ValueError: If connection with the specified ID is not found.
        """
        logger.debug("Getting SecureApp Connection with name '%s' "
                     "from application '%s'.", connection_name, app_name)
        app_id = self.get_app_by_name(app_name).id
        return self.get_connection_by_name_for_app_id(app_id, connection_name)

    def get_network_objects_list_for_app_by_id(self, app_id):
        """
        Get the list of network objects for SecureApp application by application ID.
        :param app_id: Application ID
        :type app_id: int
        :return: The list of network objects for the specified application.
        :rtype:Network_Objects_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting Network objects list for SecureApp application '%s'.", app_id)
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository"
                                           "/applications/{}/network_objects".format(app_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET network objects list for SecureApp application with id '{}'".format(app_id)
            logger.critical(message)
            raise IOError(message)
        try:
            network_objects_list = Network_Objects_List.from_xml_string(response_string)
        except (ValueError, AttributeError):
            message = "Failed to get network objects list for application with id '{}'".format(app_id)
            logger.critical(message)
            raise ValueError(message)
        return network_objects_list

    def get_all_network_objects(self):
        """
        Get the list of  all network objects in SecureApp .
        :return: The list of all network objects in SecureApp.
        :rtype: Network_Objects_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting network objects list for SecureApp.")
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/repository"
                                           "/network_objects", expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get network objects list for SecureApp."
            logger.critical(message)
            raise IOError(message)
        try:
            network_objects_list = Network_Objects_List.from_xml_string(response_string)
        except (ValueError, AttributeError):
            message = "Failed to get network objects list for SecureApp."
            logger.critical(message)
            raise ValueError(message)
        return network_objects_list

    def get_network_objects_list_for_app_name(self, app_name):
        """
        Get the SecureApp network objects list for the application whose name matches the specified name.
        :param app_name: The name of the application whose network object list will be returned.
        :type app_name: str
        :return: The  network objects list for the application whose name matches the specified name.
        :rtype:Network_Objects_List
        :raise ValueError: If an application with the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting network objects list for application with name '%s'.", app_name)
        app_id = self.get_app_by_name(app_name).id
        return self.get_network_objects_list_for_app_by_id(app_id)

    def get_network_object_by_name_for_app_id(self, network_object_name, app_id):
        """
        Get the SecureApp network object whose name matches the specified name for the application whose ID matches the
        specified ID.
        :param app_id: The ID of the application whose network objects will be returned.
        :type app_id: int
        :param network_object_name: The name of the network object which will be returned.
        :type network_object_name: str
        :return: The network object whose name matches the specified name for the application whose
        ID matches the specified ID.
        :rtype:Network_Object_DNS_Host|Network_Object_IP_Address
        :raise ValueError: If an application with the specified ID is not found and/or a network object with
        the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting network object '%s'.", network_object_name)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/network_objects".format(app_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Application with ID '{}' does not exist.".format(app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp network objects list for application with ID {}.".format(app_id)
            logger.critical(message)
            raise IOError(message)

        for network_object in Network_Objects_List.from_xml_string(response_string):
            if network_object.name == network_object_name:
                return network_object
        message = "Could not find network object with name '{}' for application with ID {}.".format(network_object_name,
                                                                                                    app_id)
        logger.critical(message)
        raise ValueError(message)

    def get_network_object_by_id_for_app_id(self, network_object_id, app_id):
        """
        Get the SecureApp network object whose id matches the specified id for the application whose ID matches the
        specified ID.
        :param app_id: The ID of the application whose network objects will be returned.
        :type app_id: int
        :param network_object_id: The id of the network object which will be returned.
        :type network_object_id: int
        :return: The network object whose id matches the specified id for the application whose
        ID matches the specified ID.
        :rtype:Network_Object_DNS_Host|Network_Object_IP_Address
        :raise ValueError: If an application with the specified ID is not found and/or a network object with
        the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting network object with id '%s'.", network_object_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/network_objects".format(app_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Application with ID '{}' does not exist.".format(app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp network objects list for application with ID {}.".format(app_id)
            logger.critical(message)
            raise IOError(message)

        for network_object in Network_Objects_List.from_xml_string(response_string):
            if network_object.id == network_object_id:
                return network_object
        message = "Could not find network object with id '{}' for application with ID {}.".format(network_object_id,
                                                                                                  app_id)
        logger.critical(message)
        raise ValueError(message)

    def post_apps(self, apps):
        """
        Create the specified SecureApp application object/objects in SecureApp.
        :param apps: The application object/objects to create in SecureApp.
        :type apps:Application or list of Application
        :rtype: bool
        :raise ValueError: If there was a problem with the parameters.
        :raise IOError: If there was a communication error.
        :return: The ID of the created application.
        If more than one object is created, (True, None) is returned.
        """
        logger.info("Creating SecureApp applications.")
        app_list = Applications_List([])
        # Handle a list of apps
        if isinstance(apps, list):
            app_list.extend(apps)
            expected_status_code = [200, 201]
            if len(apps) == 0:
                message = "The list of applications to create is empty."
                logger.critical(message)
                raise ValueError(message)
        elif isinstance(apps, Applications_List):
            app_list.extend(apps)
            expected_status_code = [200, 201]
            if len(apps) == 0:
                message = "The list of applications to create is empty."
                logger.critical(message)
                raise ValueError(message)
        elif isinstance(apps, Application):
            app_list.append(apps)
            expected_status_code = 201
        else:
            message = "The provided parameter must be a list of applications, " \
                      "Secure_App.XML_Objects.REST.Applications_List, or Application"
            logger.critical(message)
            raise ValueError(message)
        try:
            response = self.post_uri("/securechangeworkflow/api/secureapp/repository/applications/",
                                     app_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            if expected_status_code == 201:
                app_id = response.get_created_item_id()
                return app_id
            return True
        except RequestException as error:
            message = "Could not create the following applications: '{}', error was '{}'.".format(
                [app.name for app in app_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following applications: '{}', error was '{}'.".format(
                [app.name for app in app_list], error)
            logger.critical(message)
            raise ValueError(message)

    def update_app(self, apps, customer_name=None):
        """
        Update the specified SecureApp application object/objects in SecureApp.
        :param apps: The application object/objects to be updated in SecureApp.
        :type apps:Application or list of Application
        :return: Returns True or False if updated/not updated
        :rtype: bool
        :raise ValueError: If there was a problem with the parameters.
        :raise IOError: If there was a communication error.
        If more than one object is created, (True, None) is returned.
        """
        logger.info("Creating SecureApp applications.")
        app_list = Applications_List([])
        expected_status_code = [200, 201]
        # Handle a list of apps
        if isinstance(apps, list):
            app_list.extend(apps)
            if len(apps) == 0:
                message = "The list of applications to update is empty."
                logger.critical(message)
                raise ValueError(message)
        elif isinstance(apps, Applications_List):
            app_list.extend(apps)
            if len(apps) == 0:
                message = "The list of applications to update is empty."
                logger.critical(message)
                raise ValueError(message)
        elif isinstance(apps, Application):
            app_list.append(apps)
        else:
            message = "The provided parameter must be a list of applications, " \
                      "Secure_App.XML_Objects.REST.Applications_List, or Application"
            logger.critical(message)
            raise ValueError(message)
        # BUG: around for current bug that will return 200 if id is not specified but application will not be updated
        for app in app_list:
            if not app.id:
                try:
                    app.id = self.get_app_by_name(app.name, customer_name).id
                except (ValueError, AttributeError, IOError):
                    message = "Failed to get id for application '{}'.".format(app.name)
                    logger.critical(message)
                    raise ValueError(message)
        try:
            self.put_uri("/securechangeworkflow/api/secureapp/repository/applications/",
                         app_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            return True
        except RequestException as error:
            message = "Could not update the following applications: '{}', error was '{}'.".format(
                [app.name for app in app_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not update the following applications: '{}', error was '{}'.".format(
                [app.name for app in app_list], error)
            logger.critical(message)
            raise ValueError(message)

    def delete_apps(self, apps):
        """
        Delete the specified SecureApp application object/objects in SecureApp.
        :param apps: The application object/objects to create in SecureApp.
        :type apps:Application|Applications_List|list[Application]
        :return: True if the application creation was successful.
        :rtype: bool
        :raise ValueError: If the specified application does not exist or there was another problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting applications from SecureApp.")
        # Handle a list of apps
        if isinstance(apps, list):
            if len(apps) == 0:
                raise ValueError("The list of applications to delete is empty.")
            else:
                for app in apps:
                    try:
                        self.delete_uri("/securechangeworkflow/api/secureapp/repository/applications/{}".format(app.id),
                                        expected_status_codes=200)
                    except REST_Client_Error as error:
                        message = "Could not delete the following applications: '{}', error was '{}'.".format(
                            [app.name for app in apps], error)
                        logger.critical(message)
                        raise ValueError(message)
                    except RequestException as error:
                        message = "Could not delete the following applications: '{}', error was '{}'.".format(
                            [app.name for app in apps], error)
                        logger.critical(message)
                        raise IOError(message)
                return True
        # Handle Applications_List
        elif isinstance(apps, Applications_List):
            if len(apps) == 0:
                raise ValueError("The applications list to delete is empty.")
            else:
                for app in apps:
                    try:
                        self.delete_uri("/securechangeworkflow/api/secureapp/repository/applications/{}".format(app.id),
                                        expected_status_codes=200)
                    except REST_Client_Error as error:
                        message = "Could not delete the following applications: '{}', error was '{}'.".format(
                            [app.name for app in apps], error)
                        logger.critical(message)
                        raise ValueError(message)
                    except RequestException as error:
                        message = "Could not delete the following applications: '{}', error was '{}'.".format(
                            [app.name for app in apps], error)
                        logger.critical(message)
                        raise IOError(message)
                return True
        # Handle Application
        elif isinstance(apps, Application):
            try:
                self.delete_uri("/securechangeworkflow/api/secureapp/repository/applications/{}".format(apps.id),
                                expected_status_codes=200)
                return True
            except REST_Client_Error as error:
                message = "Could not delete the following application: '{}', error was '{}'.".format(
                    apps.name, error)
                logger.critical(message)
                raise ValueError(message)
            except RequestException as error:
                message = "Could not delete the following application: '{}', error was '{}'.".format(
                    apps.name, error)
                logger.critical(message)
                raise IOError(message)
        else:
            raise ValueError(
                'The provided parameter must be a list of applications,Applications_List,'
                ' or Application')

    def delete_app_by_id(self, app_id):
        """
        Delete the SecureApp application with the specified ID.
        :param app_id: The ID of the application to be deleted.
        :type app_id: int
        :return: True if successful.
        :rtype: bool
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting application with ID '%s' from SecureApp.", app_id)
        try:
            self.delete_uri("/securechangeworkflow/api/secureapp/repository/applications/{}".format(app_id),
                            expected_status_codes=200)
        except REST_Client_Error as error:
            message = "Could not delete application with ID : '{}', error was '{}'.".format(app_id, error)
            logger.critical(message)
            raise ValueError(message)
        except RequestException as error:
            message = "Could not delete application with ID : '{}', error was '{}'.".format(app_id, error)
            logger.critical(message)
            raise IOError(message)
        return True

    def delete_app_by_name(self, app_name):
        """
        Delete the SecureApp application with the specified name.
        :param app_name: The name of the application to be deleted.
        :type app_name: str
        """
        app_id = self.get_app_by_name(app_name).id
        return self.delete_app_by_id(app_id)

    def delete_all_apps(self):
        """
        Delete all configured SecureApp applications.
        :return: True if successful.
        :rtype: bool
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting all existing applications from SecureApp.")
        self._app_list = self.get_application_list()
        for app in self._app_list:
            try:
                self.delete_app_by_id(app.id)
            except (RequestException, ValueError) as delete_error:
                message = "Could not delete application with ID : '{}', error was '{}'.".format(app.id, delete_error)
                logger.critical(message)
                raise IOError(message)

        return True

    def create_users(self, users):
        """
        Create the specified SecureApp user object/objects in SecureApp.
        :param users: The user object/objects to create in SecureApp.
        :type users:User_List|User|list[User]
        :return: The ID of the created user.
        If more than one object is created, True is returned.
        :rtype: bool
        :raise ValueError: If there was a problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        logger.info("Creating SecureApp users.")
        users_list = User_List([])
        # Handle a list of users
        if isinstance(users, list):
            if len(users) == 0:
                message = "The list of users to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                users_list.extend(users_list)
                if len(users) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(users, User_List):
            if len(users) == 0:
                message = "The list of users to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                users_list.extend(users)
                if len(users) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(users, User):
            users_list.append(users)
            expected_status_code = 201
        else:
            raise ValueError(
                'The provided parameter must be a list of users,User_List, '
                'or User')
        try:
            response = self.post_uri("/securechangeworkflow/api/secureapp/repository/users/",
                                     users_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            if expected_status_code == 201:
                user_id = response.get_created_item_id()
                return user_id
            return None
        except RequestException as error:
            message = "Could not create the following users: '{}', error was '{}'.".format(
                [user.name for user in users_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following users: '{}', error was '{}'.".format(
                [user.name for user in users_list], error)
            logger.critical(message)
            raise ValueError(message)

    def delete_user_by_id(self, user_id):
        """
        Delete the SecureApp user with the specified ID.
        :param user_id: The ID of the user to be deleted.
        :type user_id: int
        :return: True if successful.
        :rtype: bool
        :raise ValueError: If a user with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting user with ID '%s' from SecureApp.", user_id)
        try:
            self.delete_uri("/securechangeworkflow/api/secureapp/repository/users/{}".format(user_id),
                            expected_status_codes=200)
        except REST_Client_Error as error:
            message = "Could not delete user with ID {}, error was '{}'.".format(user_id, error)
            logger.critical(message)
            raise ValueError(message)
        except RequestException as error:
            message = "Could not delete user with ID {}, error was '{}'.".format(user_id, error)
            logger.critical(message)
            raise IOError(message)
        return True

    def delete_user_by_name(self, user_name):
        """
        Delete the SecureApp user with the specified name.
        :param user_name: The name of the user to be deleted.
        :type user_name: string
        :return: True if successful.
        :rtype: bool
        :raise ValueError: If a user with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting user with name '%s' from SecureApp.", user_name)
        user_id = self.get_user_by_name(user_name).id
        return self.delete_user_by_id(user_id)

    def post_services(self, services, app_id=None, app_name=None):
        """
        Create the specified SecureApp services in SecureApp,
        if application id or name are specified then services will be posted to this application
        :param services: The services object/objects to create in SecureApp.
        :type services:Single_Service|Group_Service|list[Single_Service]|list[Group_Service]|Services_List
        :param app_id: The ID of application.
        :type app_id: int
        :param app_name: The name of the application.
        :type app_name: str
        :return: If the object creation was successful and only object was created,
        return the ID of the created service.
        If more than one object is created, (True, None) is returned.
        :rtype: int
        :raise ValueError: If there was a problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        info = "Creating SecureApp services"
        if app_id:
            info += " for application with ID {}".format(app_id)
            url = "/securechangeworkflow/api/secureapp/repository/applications/{}/services".format(app_id)
        elif app_name:
            info += " for application '{}'".format(app_name)
            app_id = self.get_app_by_name(app_name).id
            url = "/securechangeworkflow/api/secureapp/repository/applications/{}/services".format(app_id)
        else:
            info += "."
            url = "/securechangeworkflow/api/secureapp/repository/services/"
        logger.info(info)
        services_list = Services_List([])
        # Handle a list of services
        if isinstance(services, list):
            if len(services) == 0:
                message = "The list of services to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                services_list.extend(services)
                if len(services) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(services, Services_List):
            if len(services) == 0:
                message = "The list of services to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                services_list.extend(services)
                if len(services) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(services, (Single_Service, Group_Service)):
            services_list.append(services)
            expected_status_code = 201
        else:
            raise ValueError(
                "The provided parameter must be a list of services,Services_List, "
                "Secure_App.XML_Objects.REST.Single_Service or Group_Service")
        try:
            response = self.post_uri(url,
                                     services_list.to_xml_string().encode(),
                                     expected_status_codes=expected_status_code)
            if expected_status_code == 201:
                service_id = response.get_created_item_id()
                return service_id
            return True
        except RequestException as error:
            message = "Could not create the following services: '{}', error was '{}'".format(
                [service.name for service in services_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following services: '{}', error was '{}'".format(
                [service.name for service in services_list], error)
            logger.critical(message)
            raise ValueError(message)

    def update_services(self, services, app_id=None, app_name=None):
        """
        Update the specified SecureApp services in SecureApp,
        if application ID or name are specified then services will be updated for this application
        :param services: The services object/objects to update in SecureApp for application.
        :type services:Single_Service|Group_Service|[Single_Service]|[Group_Service]|Services_List
        :param app_id: The Application ID.
        :type app_id: int
        :param app_name: The Application name
        :type app_name: str
        :raise ValueError: If there was a problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        info = "Updating services for SecureApp"
        if app_id:
            info += " for application with ID {}".format(app_id)
            url = "/securechangeworkflow/api/secureapp/repository/applications/{}/services".format(app_id)
        elif app_name:
            info += " for application '{}'".format(app_name)
            app_id = self.get_app_by_name(app_name).id
            url = "/securechangeworkflow/api/secureapp/repository/applications/{}/services".format(app_id)
        else:
            info += "."
            url = "/securechangeworkflow/api/secureapp/repository/services/"
        logger.info(info)
        services_list = Services_List([])
        # Handle a list of services
        if isinstance(services, list):
            if len(services) == 0:
                message = "The list of services to update is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                services_list.extend(services)
        elif isinstance(services, Services_List):
            if len(services) == 0:
                message = "The list of services to update is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                services_list.extend(services)
        elif isinstance(services, (Single_Service,
                                   Group_Service)):
            services_list.append(services)
        else:
            raise ValueError(
                "The provided parameter must be a list of services,Services_List, "
                "Secure_App.XML_Objects.REST.Single_Service or Group_Service")
        try:
            self.put_uri(url,
                         services_list.to_xml_string().encode(),
                         expected_status_codes=200)
        except RequestException as error:
            message = "Could not update the following services: '{}', error was '{}'".format(
                [service.name for service in services_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not update the following services: '{}', error was '{}'".format(
                [service.name for service in services_list], error)
            logger.critical(message)
            raise ValueError(message)

    def delete_service_by_name(self, service_name):
        """
        Delete the SecureApp service with the specified name.
        :param service_name: The name of the SecureApp service that will be deleted.
        :type service_name: str
        :return: True if the service deletion was successful.
        :rtype: bool
        :raise ValueError: If the specified service does not exist or there was another problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting service with name '%s' from SecureApp.", service_name)
        try:
            self.delete_uri("/securechangeworkflow/api/secureapp/repository/services?name={}".format(service_name),
                            expected_status_codes=200)
        except RequestException as error:
            message = "Could not delete the service: '{}', error was '{}'".format(service_name, error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not delete the service: '{}', error was '{}'".format(service_name, error)
            logger.critical(message)
            raise ValueError(message)
        return True

    def delete_local_service(self, app_id, service_id):
        """Delete local service with in application in SecureApp.
        :param app_id: The id of the application
        :param service_id: The local service id
        :return: True if the service deletion was successful.
        :raise ValueError: If the specified service does not exist or there was another problem with the parameters.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting local service id '{}' for application id '{}'".format(app_id, service_id))
        url = "/securechangeworkflow/api/secureapp/repository/applications/{}/services/{}".format(app_id, service_id)
        try:
            self.delete_uri(url, expected_status_codes=200)
        except RequestException as error:
            message = "Could not delete service with ID: '{}', error was '{}'".format(service_id, error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not delete service with ID: '{}', error was '{}'".format(service_id, error)
            logger.critical(message)
            raise ValueError(message)
        return True

    def delete_service_by_id(self, service_id):
        """
        Delete the SecureApp service with the specified ID.
        :param service_id: The ID of the service to be deleted.
        :type service_id: int
        :return: True if successful.
        :rtype: bool
        :raise ValueError: If an service with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Deleting service with ID '%s' from SecureApp.", service_id)
        try:
            self.delete_uri("/securechangeworkflow/api/secureapp/repository/services/{}".format(service_id),
                            expected_status_codes=200)
        except REST_Client_Error as error:
            message = "Could not delete the service with ID '{}', error was '{}'".format(service_id, error)
            logger.critical(message)
            raise ValueError(message)
        except RequestException as error:
            message = "Could not delete the service with ID '{}', error was '{}'".format(service_id, error)
            logger.critical(message)
            raise IOError(message)
        return True

    def create_network_objects_for_app_id(self, app_id, network_objects):
        """
        Create the specified network objects for the application with the specified ID.
        :param app_id: The ID of the application that network objects will be created for.
        :type app_id: int
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        :return: The ID of the created network object.
        If more than one object is created, True is returned.
        """
        logger.info("Creating network objects for application with ID '%s'.", app_id)
        network_objects_list = Network_Objects_List([])
        # Handle a list of network objects
        if isinstance(network_objects, list):
            if len(network_objects) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                network_objects_list.extend(network_objects)
                if len(network_objects) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(network_objects, Network_Objects_List):
            if len(network_objects) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                network_objects_list.extend(network_objects)
                if len(network_objects_list) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(network_objects, (
                Basic_Network_Object, Range_Network_Object,
                Host_Network_Object, Subnet_Network_Object,
                Group_Network_Object)):
            network_objects_list.append(network_objects)
            expected_status_code = 201
        else:
            raise ValueError(
                "The provided parameter must be a list of network objects, "
                "Secure_App.XML_Objects.REST.Network_Objects_List,Basic_Network_Object, "
                "Secure_App.XML_Objects.REST.Range_Network_Object,Host_Network_Object, "
                "Secure_App.XML_Objects.REST.Subnet_Network_Object or Group_Network_Object")
        try:
            response = self.post_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{0}/network_objects".format(app_id),
                network_objects_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            if expected_status_code == 201:
                network_object_id = response.get_created_item_id()
                return network_object_id
            return True
        except RequestException as error:
            message = "Could not create the following network objects: '{}', error was '{}'".format(
                [network_object.name for network_object in network_objects_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following network objects: '{}', error was '{}'".format(
                [network_object.name for network_object in network_objects_list], error)
            logger.critical(message)
            raise ValueError(message)

    def update_network_objects_for_app_id(self, app_id, network_objects):
        """
        Update the specified network objects for the application with the specified ID.
        :param app_id: The ID of the application that network objects will be updated for.
        :type app_id: int
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        :return: If success true is returned.
        :rtype: bool
        """
        logger.info("Updating network objects for application with ID '%s'.", app_id)
        network_objects_list = Network_Objects_List([])
        expected_status_code = 200
        # Handle a list of network objects
        if isinstance(network_objects, list):
            if len(network_objects) == 0:
                message = "The list of network objects to update is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                network_objects_list.extend(network_objects)
        elif isinstance(network_objects, Network_Objects_List):
            if len(network_objects) == 0:
                message = "The list of network objects to update is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                network_objects_list.extend(network_objects)
        elif isinstance(network_objects, (
                Basic_Network_Object, Range_Network_Object,
                Host_Network_Object, Subnet_Network_Object,
                Group_Network_Object)):
            network_objects_list.append(network_objects)
        else:
            raise ValueError(
                "The provided parameter must be a list of network objects, "
                "Secure_App.XML_Objects.REST.Network_Objects_List,Basic_Network_Object, "
                "Secure_App.XML_Objects.REST.Range_Network_Object,Host_Network_Object, "
                "Secure_App.XML_Objects.REST.Subnet_Network_Object or Group_Network_Object")
        for network_object in network_objects_list:
            if not any((network_object.id, network_object.name)):
                message = "One of the network objects does not have neither name nor id"
                raise ValueError(message)
            elif not network_object.id:
                try:
                    network_object.id = self.get_network_object_by_name_for_app_id(network_object.name, app_id)
                except (ValueError, AttributeError, IOError):
                    message = "Failed to get id for a network object '{}'".format(network_object.name)
                    logger.critical(message)
                    raise ValueError(message)
            elif not network_object.name:
                try:
                    network_object.name = self.get_network_object_by_id_for_app_id(network_object.id, app_id)
                except (ValueError, AttributeError, IOError):
                    message = "Failed to get name for a network object with id '{}'".format(network_object.id)
                    logger.critical(message)
                    raise ValueError(message)
            else:
                continue
        try:
            self.put_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/network_objects".format(app_id),
                network_objects_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            return True
        except RequestException as error:
            message = "Could not create the following network objects: '{}', error was '{}'".format(
                [network_object.name for network_object in network_objects_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following network objects: '{}', error was '{}'".format(
                [network_object.name for network_object in network_objects_list], error)
            logger.critical(message)
            raise ValueError(message)

    def create_network_objects_for_app_name(self, app_name, network_objects):
        """
        Create the specified network objects for the application with the specified name.
        :param app_name: The ID of the application that network objects will be created for.
        :type app_name: str
        :return: If the object creation was successful and only object was created, return is (True, object_id), where
        object_id is the ID of the created object that is extracted from the Location header.
        If more than one object is created, (True, None) is returned.
        """
        app_id = self.get_app_by_name(app_name).id
        return self.create_network_objects_for_app_id(app_id, network_objects)

    def update_network_objects_for_app_name(self, app_name, network_objects):
        """
        Update the specified network objects for the application with the specified name.
        :param app_name: The ID of the application that network objects will be updated for.
        :type app_name: str
        :return: If the object update was successful True is returned
        """
        app_id = self.get_app_by_name(app_name).id
        return self.update_network_objects_for_app_id(app_id, network_objects)

    def create_connections_for_app_id(self, app_id, connections):
        """
        Create the specified network objects for the application with the specified ID.
        :param app_id: The ID of the application that connections will be created for.
        :type app_id: int
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        :return: The ID of the created connection.
        If more than one object is created, True is returned.
        """
        logger.info("Creating network objects for application with ID '%s'.", app_id)

        connection_list = Connection_List([])
        # Handle a list of services
        if isinstance(connections, list):
            if len(connections) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                connection_list.extend(connections)
                if len(connection_list) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(connections, Connection_List):
            if len(connections) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                connection_list.extend(connections)
                if len(connection_list) == 1:
                    expected_status_code = 201
                else:
                    expected_status_code = 200
        elif isinstance(connections, Detailed_Application_Connection):
            connection_list.append(connections)
            expected_status_code = 201
        else:
            raise ValueError(
                "The provided parameter must be a list of connections objects, "
                "Secure_App.XML_Objects.REST.Connection_List,"
                "Detailed_Application_Connection")
        try:
            response = self.post_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections".format(app_id),
                connection_list.to_xml_string().encode(), expected_status_codes=expected_status_code)
            if expected_status_code == 201:
                connection_id = response.get_created_item_id()
                return connection_id
            return True
        except RequestException as error:
            message = "Could not create the following connections: '{}', error was '{}'.".format(
                [connection.name for connection in connection_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create the following connections: '{}', error was '{}'.".format(
                [connection.name for connection in connection_list], error)
            logger.critical(message)
            raise ValueError(message)

    def create_connections_for_app_name(self, app_name, connections):
        """
        Create the specified connections objects for the application with the specified name.
        :param app_name: The ID of the application that connections will be created for.
        :type app_name: str
        :return: If the object creation was successful and only object was created, return is (True, object_id), where
        object_id is the ID of the created object that is extracted from the Location header.
        If more than one object is created, (True, None) is returned.
        """
        logger.info("Creating connections for application '%s'", app_name)
        app_id = self.get_app_by_name(app_name).id
        return self.create_connections_for_app_id(app_id, connections)

    def update_connection_for_app_id(self, connection, app_id=None, app_name=None):
        """
        Update existing connection with new one. Or ID or name of
            application the connection belongs to should be provided
        :param connection: The new connection to update with
        :type connection:Detailed_Application_Connection
        :param app_id: The Id of application to update connection for
        :type app_id: int
        :param app_name: The name of application to update connection for
        :type app_name: str
        :raise IOError: If there is communication or API error
        :raise ValueError: if one of the parameters is wrong one
        """
        if not (app_id or app_name):
            msg = "No ID or name of application of connection to update is provided"
            logger.critical(msg)
            raise ValueError(msg)
        elif not app_id:
            app_id = self.get_app_by_name(app_name).id

        if not connection.id and not connection.name:
            msg = "No ID or name of connection to update is provided"
            logger.critical(msg)
            raise ValueError(msg)
        elif not connection.id:
            logger.info("Updating connection '{}' "
                        "for application with ID {}".format(connection.name,
                                                            app_id))
            connection.id = self.get_connection_by_name_for_app_id(app_id, connection.name).id
        else:
            logger.info("Updating connection with ID {} "
                        "for application with ID {}".format(connection.id,
                                                            app_id))

        try:
            self.put_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections/{}".format(
                    app_id,
                    connection.id),
                connection.to_xml_string().encode(),
                expected_status_codes=200)
        except RequestException:
            message = "Failed to update connection with ID {}" \
                      " for application with ID {}".format(connection.id,
                                                           app_id)
            logger.critical(message)
            raise IOError(message)

    def update_connections_for_app(self, connections, app_id=None, app_name=None):
        """
        Update the specified network objects for the application with the specified ID.
        :param app_id: The ID of the application that connections will be created for.
        :type app_id: int
        :param app_name: The name of the application that connections will be created for.
        :type app_name: str
        :raise ValueError: If an application with the specified ID is not found.
        :raise IOError: If there was a communication error.
        If more than one object is created, True is returned.
        """
        if not app_id and not app_name:
            msg = "ID or name of application to update connections for is not provided"
            logger.critical(msg)
            raise ValueError(msg)
        elif not app_id:
            app_id = self.get_app_by_name(app_name).id

        logger.info("Updating network objects for application with ID '%s'.", app_id)

        connection_list = Connection_List([])
        # Handle a list of services
        if isinstance(connections, list):
            if len(connections) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                connection_list.extend(connections)
        elif isinstance(connections, Connection_List):
            if len(connections) == 0:
                message = "The list of network objects to create is empty."
                logger.critical(message)
                raise ValueError(message)
            else:
                connection_list.extend(connections)
        elif isinstance(connections, Detailed_Application_Connection):
            connection_list.append(connections)
        else:
            raise ValueError(
                "The provided parameter must be a list of connections objects, "
                "Secure_App.XML_Objects.REST.Connection_List,"
                "Detailed_Application_Connection")
        try:
            self.put_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections".format(app_id),
                connection_list.to_xml_string().encode(), expected_status_codes=200)
            return True
        except RequestException as error:
            message = "Could not update the following connections: '{}', error was '{}'.".format(
                [connection.name for connection in connection_list], error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not update the following connections: '{}', error was '{}'.".format(
                [connection.name for connection in connection_list], error)
            logger.critical(message)
            raise ValueError(message)

    def delete_connection_by_id_for_app_id(self, app_id=None, app_name=None, connection_id=None, connection_name=None):
        """
        Delete connection by it's ID from application of provided application ID
        :param app_id: Application ID to delete connection from
        :type app_id: int
        :param app_name: Application name
        :type app_name: str
        :param connection_id: Connection ID to delete from Application
        :type connection_id: int
        :param connection_name: Connection name
        :type connection_name: str
        :raise IOError: If there was communication error.
        """
        if not app_id and not app_name:
            ValueError("Failed to delete connection, as no application ID or name specified")
        elif not app_id:
            app_id = self.get_app_by_name(app_name).id
        if not connection_id and not connection_name:
            ValueError("Failed to delete connection, no connection ID or name specified")
        elif not connection_id:
            connection_id = self.get_connection_by_name_for_app_id(app_id, connection_name).id

        logger.info("Deleting Connection with ID %s from application with ID %s", connection_id, app_id)
        try:
            self.delete_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections/{}".format(
                    app_id,
                    connection_id),
                expected_status_codes=200)
        except RequestException:
            message = "Failed to delete connection with ID {} from SecureApp for Application with ID {}".format(
                connection_id,
                app_id)
            logger.critical(message)
            raise IOError(message)

    def delete_all_connections_for_app(self, app_id=None, app_name=None):
        """
        Delete all connections of specified application(by ID or name)
        :param app_id:
        :param app_name:
        :raise IOError: If there were communication problems
        :raise ValueError: If no app was found or wrong paramaters passed
        """
        if not app_id and not app_name:
            raise ValueError("Can't delete connections as no application name or id specified")
        if not app_id:
            app_id = self.get_app_by_name(app_name).id
        logger.info("Deleting all connection from application with ID %s", app_id)
        connections = [connection for connection in self.get_connections_list_for_app_id(app_id)]
        if connections:
            deleted_connections = []

            for connection in connections:
                try:
                    self.delete_uri(
                        "/securechangeworkflow/api/secureapp/repository/applications/{}/connections/{}".format(
                            app_id,
                            connection.id),
                        expected_status_codes=200)
                except RequestException as error:
                    connections_names = (con.name for con in connections)
                    if deleted_connections:
                        message = "Failed to delete all connections. Deleted '{}' out of '{}'." \
                                  " Got error on connection '{}': {}".format(
                            deleted_connections,
                            connections_names,
                            connection.name,
                            error)
                    else:
                        message = "Failed to delete connections '{}'. Got error on connection '{}': {}".format(
                            connections_names,
                            connection.name,
                            connections_names)
                    logger.critical(message)
                    raise IOError(message)
                else:
                    deleted_connections.append(connection.name)

    def get_connections_to_applications(self, app_id):
        """
        Get connections to application for application
        :param app_id: Application ID
        :type app_id: str|int
        :return: Connections_To_Applications
        """
        logger.info("Getting Connections to application for Application with ID {}".format(app_id))
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/connections_to_applications".format(
                app_id)).response.content
        except RequestException:
            message = "Failed to get connections to application for app with ID {}".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Connections_To_Applications.from_xml_string(response_string)

    def get_connection_to_application(self, app_id, conn_to_app_id):
        """
        Get connection to application by ID for application
        :param app_id: Application ID
        :type app_id: str|int
        :param conn_to_app_id: Id of the connection to application
        :type conn_to_app_id: str|int
        :return: Connections_To_Applications
        """
        logger.info("Getting Connection to Application with ID {} for Application with ID {}".format(
            conn_to_app_id, app_id))
        try:
            response_string = self.get_uri("securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/connections_to_applications/{}".format(
                                               app_id, conn_to_app_id)).response.content
        except REST_Not_Found_Error:
            message = "Connection to Application with ID '{}' does not exist in Application with ID {}.".format(
                conn_to_app_id, app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get connection to application  with ID {} for app with ID {}".format(
                conn_to_app_id, app_id)
            logger.critical(message)
            raise IOError(message)
        return Connection_To_Application.from_xml_string(response_string)

    def get_application_interfaces(self, app_id):
        """
            Get application interfaces for application
            :param app_id: Application ID
            :type app_id: str|int
            :return: Application_Interfaces
        """
        logger.info("Getting appplication interfaces for Application with ID {}".format(app_id))
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/application_interfaces".format(
                app_id)).response.content
        except RequestException:
            message = "Failed to get connections to application for app with ID {}".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Application_Interfaces.from_xml_string(response_string)

    def get_application_interface(self, app_id, app_interface_id):
        """
            Get application interfaces by ID for application
            :param app_id: Application ID
            :type app_id: str|int
            :param app_interface_id: Application Interface ID
            :type app_interface_id: int|str
            :return: Application_Interface
        """
        logger.info("Getting Application Interface with ID {} for Application with ID {}".format(
            app_interface_id, app_id))
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/application_interfaces/{}".format(
                                               app_id, app_interface_id)).response.content
        except REST_Not_Found_Error:
            message = "Application Interface  with ID '{}' does not exist in Application with ID {}.".format(
                app_interface_id, app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get Application Interface  with ID {} for app with ID {}".format(
                app_interface_id, app_id)
            logger.critical(message)
            raise IOError(message)
        return Connection_To_Application.from_xml_string(response_string)

    def get_connection_to_application_pack(self, app_id, con_to_app_pack_id):
        """
            Get connection to application packs for application
            :param app_id: Application ID
            :type app_id: str|int
            :param con_to_app_pack_id: ID of the connection to Application Pack
            :type con_to_app_pack_id: int|str
            :return: Connection_To_Application_Pack
        """
        logger.info("Getting connection to applicaton pack {} for Application with ID {}".format(
            con_to_app_pack_id, app_id))
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/connection_to_application_packs/{}".format(
                                               app_id, con_to_app_pack_id)).response.content
        except REST_Not_Found_Error:
            message = "Connection to application pack with ID '{}' does not exist in Application with ID {}.".format(
                con_to_app_pack_id, app_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get connection to applicaton pack {} for app with ID {}".format(
                con_to_app_pack_id, app_id)
            logger.critical(message)
            raise IOError(message)
        return Detailed_Connection_To_Application_Pack.from_xml_string(response_string)

    def get_connection_to_application_packs(self, app_id):
        """
            Get connection to application packs for application
            :param app_id: Application ID
            :type app_id: str|int
            :return: Connection_To_Application_Packs
        """
        logger.info("Getting connection to applicaton packs for Application with ID {}".format(app_id))
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/"
                                           "repository/applications/{}/connection_to_application_packs".format(
                                               app_id)).response.content
        except RequestException:
            message = "Failed to get connection to applicaton packs for app with ID {}".format(app_id)
            logger.critical(message)
            raise IOError(message)
        return Connection_To_Application_Packs.from_xml_string(response_string)

    def get_customers(self):
        """
        Get the list of currently configured SecureApp customers.
        :return: The list of currently configured SecureApp customers.
        :rtype:Customers_List
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp customers list.")
        try:
            response_string = self.get_uri("/securechangeworkflow/api/secureapp/customers",
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET SecureApp customers list"
            logger.critical(message)
            raise IOError(message)
        self._customers_list = Customers_List.from_xml_string(response_string)
        return self._customers_list

    def get_customer_by_id(self, customer_id):
        """
        Get the SecureApp customer whose ID matches the specified ID.
        :param customer_id: The ID for the customer which will be returned.
        :type customer_id: int
        :return: The customer whose ID matches the specified ID.
        :rtype:Customer
        :raise ValueError: If an customer with the specified ID is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp customer with ID '%s'.", customer_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/customers/{}".format(customer_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Customer with ID '{}' does not exist.".format(customer_id)
            logger.critical(message)
            raise ValueError(message)
        except REST_Bad_Request_Error:
            message = "Failed to GET SecureApp customer. Check if you are not in a single mode".format(customer_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp customer."
            logger.critical(message)
            raise IOError(message)
        return Customer.from_xml_string(response_string)

    def get_customer_by_name(self, customer_name):
        """
        Get the SecureApp customer whose name matches the specified name.
        :param customer_name: The name for the customer which will be returned.
        :type customer_name: str
        :return: The customer whose name matches the specified name.
        :rtype:Customer
        :raise ValueError: If the customer with the specified name is not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp customer with name '%s'.", customer_name)
        self.get_customers()
        for customer in self._customers_list:
            if customer.name == customer_name:
                return customer
        message = "The customer with the name '{}' does not exist.".format(customer_name)
        logger.critical(message)
        raise ValueError(message)

    def get_applications_of_customer_by_id(self, customer_id):
        """
        Get the SecureApp applications of the customer by his id
        :param customer_id: An id of the customer whose applications we return
        :type customer_id: int
        :return: Applications of the customer specified by id
        :rtype: Secure_App_Helper.XML_Objects.REST.Applications_List
        :raise ValueError: If failed to get customer's applications
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp applications of customer with id '%s'.", customer_id)
        try:
            response_string = self.get_uri(
                "/securechangeworkflow/api/secureapp/customers/{}/applications".format(customer_id),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Customer with ID '{}' does not exist.".format(customer_id)
            logger.critical(message)
            raise ValueError(message)
        except REST_Bad_Request_Error:
            message = "Failed to get  applications of customer with ID '{}'. Bad request.".format(customer_id)
            logger.critical(message)
            raise ValueError(message)
        except REST_Unauthorized_Error:
            message = "Failed to get  applications of customer with ID '{}'. Access is denied.".format(customer_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET SecureApp customer's applications."
            logger.critical(message)
            raise IOError(message)
        return Applications_List.from_xml_string(response_string)

    def get_applications_of_customer_by_name(self, customer_name):
        """
        Get applications of customer by his name
        :param customer_name: the name of the customer
        :type customer_name: str
        :return: Applications of the customer specified by id
        :rtype: Secure_App_Helper.XML_Objects.REST.Applications_List
        :raise ValueError: If failed to get customer's applications
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting SecureApp applications of customer with name '%s'.", customer_name)
        customer = self.get_customer_by_name(customer_name)
        return self.get_applications_of_customer_by_id(customer.id)

    def get_member_network_objects_for_group_network_object(self, group_network_object,
                                                            get_members_for_nested_groups=True,
                                                            all_network_objects=None):
        """
        :param group_network_object:
        :type group_network_object: Group_Network_Object
        :return:
        """
        logger.info("Getting member network objects for network object with ID %s.", group_network_object.id)
        if all_network_objects is None:
            all_network_objects = {network_object.id: network_object for network_object in
                                   self.get_all_network_objects()}
        network_objects = []
        for member in group_network_object.members:
            member = all_network_objects[member.id]
            if get_members_for_nested_groups:
                logger.debug("Getting nested member objects for network object with ID '%s'.", member.id)
                if hasattr(member, "members"):
                    sub_member_objects = self.get_member_network_objects_for_group_network_object(member,
                                                                                                  get_members_for_nested_groups,
                                                                                                  all_network_objects)
                    network_objects.extend(sub_member_objects)
                else:
                    network_objects.append(member)
            else:
                network_objects.append(member)
        return network_objects

    def get_member_services_for_group_service(self, group_service, get_members_for_nested_groups=True,
                                              all_services=None):
        """
        :param group_service:
        :type group_service: Group_Service
        :return:
        """
        logger.info("Getting member services for service with ID %s.", group_service.id)
        if all_services is None:
            all_services = {service.id: service for service in self.get_all_services()}
        services = []
        for member in group_service.members:
            member = all_services[member.id]
            if get_members_for_nested_groups:
                logger.debug("Getting nested services for service with ID '%s'.", member.id)
                if hasattr(member, "members"):
                    sub_member_objects = self.get_member_services_for_group_service(member,
                                                                                    get_members_for_nested_groups,
                                                                                    all_services)
                    services.extend(sub_member_objects)
                else:
                    services.append(member)
            else:
                services.append(member)
        return services

    def get_details_from_reference(self, Reference_Object, Object_Class=None,
                                   xml_from_string_func=None):
        """
        :param Reference_Object: The Reference Object
        :type Reference_Object: Base_Link_Target
        :param Object_Class: Class of the object to return to
        :return: Detailed information from referenced object
        """
        logger.info("Getting details for reference")
        try:
            link = Reference_Object.get_reference_link()
            # TODO: check function that represents uri as an object.
            api_part = link.split("securechangeworkflow/api/")[1]
            logger.info("Reference call is /securechangeworkflow/api/{}".format(api_part))
            try:
                response_string = self.get_uri(
                    "/securechangeworkflow/api/{}".format(api_part),
                    expected_status_codes=200).response.content
            except RequestException:
                message = "Failed to GET SecureApp customer's applications."
                logger.critical(message)
                raise IOError(message)
            if xml_from_string_func:
                return xml_from_string_func(response_string)
            return Object_Class.from_xml_string(response_string)

        except (KeyError, AttributeError, IOError, TypeError, IndexError) as error:
            logger.critical("Failed to get details about the reference. Error: {}".format(error))
            raise ValueError("Failed to get details about the reference.")

    def create_connection_repair_ticket(self, app_id, connection_id, ticket):
        """
        :param app_id: The ID of the application whose connections will be repaired.
        :type app_id: int
        :param connection_id: The ID of the connection to be repaired.
        :type connection_id: int
        :param ticket: The ticket that will be created to repair the connection.
        :type ticket: Secure_Change.XML_Objects.REST.Ticket
        :return: The ID of the ticket that was created to repair the connection.
        :rtype int
        :raise ValueError: If the ticket parameters were incorrect.
        :raise IOError: If there was a communication error.
        """

        logger.info("Creating connection repair ticket for application with ID %s, connection ID %s ", app_id,
                    connection_id)
        ticket_xml = ticket.to_xml_string().encode()
        logger.debug("Ticket data: '%s'", ticket_xml)
        try:
            response = self.post_uri(
                "/securechangeworkflow/api/secureapp/repository/applications/{}/connections/{}/repair".format(app_id,
                                                                                                             connection_id),
                ticket_xml, expected_status_codes=201)
            ticket_id = response.get_created_item_id()
            return ticket_id
        except RequestException as error:
            message = "Could not create a connection repair ticket for for application with ID '{}', connection ID '{}' , error was '{}'.".format(
                app_id, connection_id, error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as error:
            message = "Could not create a connection repair ticket for for application with ID '{}', connection ID '{}' , error was '{}'.".format(
                app_id, connection_id, error)
            logger.critical(message)
            raise ValueError(message)

    def get_cloud_console_servers(self, vendor, search_string):
        """ Get the list of cloud network objects in SecureApp .

        :return: The list of cloud network objects in SecureApp.
        :rtype: VM_Instances
        :raise IOError: If there was a communication error.
        """
        logger.info("Getting cloud network objects for SecureApp.")
        uri = "/securechangeworkflow/api/secureapp/cloud_console/servers?vendor={}&search_string={}".format(vendor,
                                                                                                            search_string)
        try:
            response_string = self.get_uri(uri, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get cloud console servers for SecureApp."
            logger.critical(message)
            raise IOError(message)
        try:
            cloud_console_servers = VM_Instances.from_xml_string(response_string)
        except (ValueError, AttributeError):
            message = "Failed to get cloud console servers for SecureApp."
            logger.critical(message)
            raise ValueError(message)
        return cloud_console_servers

