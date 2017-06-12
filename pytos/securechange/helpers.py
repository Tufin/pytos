
import codecs
import copy
import datetime
import logging
import os
import re
import sys
import time
import traceback
import xml.etree.ElementTree as ET
import requests

from pytos.common.definitions import xml_tags
from pytos.common.exceptions import REST_Not_Found_Error, REST_Bad_Request_Error, REST_Unauthorized_Error
from pytos.common.helpers import Secure_API_Helper
from pytos.common.logging.definitions import HELPERS_LOGGER_NAME
from pytos.common.functions import xml_node_from_string, read_multiline_str_from_stdin, get_iana_services, \
    get_csv_parser, calculate_quad_dotted_netmask
from pytos.common.definitions.xml_tags import Attributes, Elements
from pytos.securechange.xml_objects.base_types import Step_Field_Base
from pytos.securechange.xml_objects.rest import Ticket, Ticket_History_Activities, Comment, Step_Task, \
    MultiGroupChangeImplementResult, User_List, User, Group, TicketList, Reassign_Comment, Redo_Comment
from pytos.securechange.xml_objects.restapi.step.access_request.accessrequest import DNS_Access_Request_Target, \
    IP_Access_Request_Target, IP_Range_Access_Request_Target, Any_Access_Request_Target, Internet_Access_Request_Target, \
    Object_Access_Request_Target, Named_Access_Request_Device, Any_Access_Request_Device, Any_Service_Target, \
    Protocol_Service_Target, Predefined_Service_Target, Access_Request
from pytos.securechange.xml_objects.restapi.step.access_request.verifier import AccessRequestVerifierResult
from pytos.securechange.xml_objects.securechange_api import Ticket_Info


UDP = "udp"
TCP = "tcp"

logger = logging.getLogger(HELPERS_LOGGER_NAME)


class Secure_Change_Helper(Secure_API_Helper):
    """This class  is used to interact via REST with SecureChange.
    It also allows writing to the SecureChange Message Board.
    """
    CONFIG_PARSER_SECTION_NAME = "securechange"

    def __init__(self, hostname, login_data, **kwargs):
        """
        :param hostname: The SecureChange hostname with which we will communicate via HTTP.
        :type hostname: str
        :param login_data: A tuple of (username,password) used for basic authentication with the specified hostname.
        :type login_data: tuple
        :param message_board_enabled: (Optional) If set to False, Message Board functionality will be disabled.
        :type message_board_enabled: bool
        """
        super().__init__(hostname, login_data, **kwargs)

    @staticmethod
    def read_ticket_info():
        """This function reads a SecureChange ticket_info from STDIN and returns a Ticket_Info object

        :return: The Ticket_Info object that was created from the XML input.
        :rtype: Secure_Change.XML_Objects.Secure_Change_API.Ticket_Info
        @raise ValueError if the XML string can not be parsed to a valid Ticket_Info object
        """
        ticket_info_xml_string = read_multiline_str_from_stdin()
        logger.debug("Got the following XML input:\n%s", ticket_info_xml_string)
        try:
            ticket_info_doc = ET.fromstring(ticket_info_xml_string)
        except ET.ParseError as parse_error:
            logger.error("Could not parse ticket info XML.")
            raise ValueError(parse_error)
        try:
            ticket_info = Ticket_Info(ticket_info_doc)
        except ValueError:
            message = "Got empty ticket info object, assuming test mode."
            logger.info(message)
            raise ValueError(message)
        except AttributeError:
            logger.error("Could not parse ticket_info XML.")
            raise AttributeError("Could not parse ticket_info XML.")
        return ticket_info

    @staticmethod
    def read_ticket_template(ticket_template_path):
        """Read a ticket XML from a file and create a Ticket object from it.

        :param ticket_template_path: The path to the file containing the ticket XML.
        :type ticket_template_path: str
        :return: The created ticket object.
        :rtype: Ticket
        :raise FileNotFoundError: If the ticket template file was not found.
        """
        logger.debug("Reading ticket template from %s", ticket_template_path)
        try:
            with codecs.open(ticket_template_path, 'r', 'utf-8') as ticket_template_file:
                ticket_xml_string = ticket_template_file.read()
                ticket_xml_node = ET.fromstring(ticket_xml_string)
        except FileNotFoundError:
            message = "The file {} does not exist.".format(ticket_template_path)
            logger.error(message)
            raise FileNotFoundError(message)
        else:
            return Ticket.from_xml_node(ticket_xml_node)

    @staticmethod
    def get_time_in_ticket_comment_format():
        """
        Get the current time in the format used for ticket comment entries.
        """
        time_string = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f%z")
        time_string = re.sub(r"(.*\.[0-9]{3})[0-9]{3}(.*)", r"\1\2", time_string)
        return time_string

    def get_ticket_by_id(self, ticket_id, retry_until_assigned=False, sleep_time=5, retry_count=50, predicate=None):
        """Get a specific ticket by ID.

        :param ticket_id: The numeric ID of the ticket that will be returned.
        :type ticket_id: int
        :return: The ticket whose ID matches the specified ticket_id.
        :rtype: Ticket
        :raise ValueError: If a ticket with the specified ID was not found.
        :raise IOError: If there was a communication error.
        """

        if retry_until_assigned and predicate:
            raise ValueError("'retry_until_assigned' and 'predicate' should not be used at the same time")

        def _get_ticket():
            try:
                response_string = self.get_uri("/securechangeworkflow/api/securechange/tickets/{}".format(ticket_id),
                                               expected_status_codes=200).response.content
            except REST_Not_Found_Error:
                message = "Ticket with ID {} does not exist.".format(ticket_id)
                logger.error(message)
                raise ValueError(message)
            except requests.RequestException:
                message = "Failed to GET ticket ID {}.".format(ticket_id)
                logger.error(message)
                raise IOError(message)
            xml_node = xml_node_from_string(response_string)
            return Ticket.from_xml_node(xml_node)

        logger.debug("Getting ticket with ID '%s' from SecureChange", ticket_id)
        if retry_until_assigned:
            ticket_unassigned = True
            while ticket_unassigned and retry_count > 0:
                retry_count -= 1
                ticket = _get_ticket()
                try:
                    current_step = ticket.get_current_step()
                except KeyError:
                    logger.info("Ticket is closed, not waiting.")
                    return ticket
                else:
                    ticket_unassigned = current_step.get_last_task().is_waiting_to_be_assigned()
                    if ticket_unassigned:
                        time.sleep(sleep_time)
                    else:
                        return ticket
        elif predicate is not None:
            ticket = _get_ticket()
            while not predicate(ticket):
                ticket = _get_ticket()
            else:
                return ticket
        else:
            return _get_ticket()

    def get_ticket_history_by_id(self, ticket_id):
        """Get the history for a specific ticket by ID.

        :param ticket_id: The numeric ID of the ticket for which history will be returned.
        :type ticket_id: int
        :return: The ticket history for the specified ticket.
        :rtype: Ticket_History_Activities
        :raise ValueError: If a ticket with the specified ID was not found.
        :raise IOError: If there was a communication error.
        """
        try:
            response_string = self.get_uri(
                    "/securechangeworkflow/api/securechange/tickets/{}/history".format(ticket_id),
                    expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Ticket with ID {} does not exist.".format(ticket_id)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException:
            message = "Failed to GET history for ticket ID {}.".format(ticket_id)
            logger.error(message)
            raise IOError(message)
        xml_node = ET.fromstring(response_string)
        return Ticket_History_Activities.from_xml_node(xml_node)

    def post_ticket(self, ticket_obj):
        """Create a new ticket.

        :param ticket_obj: The ticket that will be created.
        :type ticket_obj: Ticket
        :return: The ID of the created ticket.
        :rtype: int
        :raise ValueError: If a ticket with the specified ID was not found.
        :raise IOError: If there was a communication error.
        """
        logger.info("Creating ticket in SecureChange.")
        ticket_xml = ticket_obj.to_xml_string().encode()
        logger.debug("Ticket data: '%s'", ticket_xml)
        try:
            response = self.post_uri("/securechangeworkflow/api/securechange/tickets/", ticket_xml,
                                     expected_status_codes=201)
            ticket_id = response.get_created_item_id()
            return ticket_id
        except REST_Bad_Request_Error as create_error:
            message = "Could not create ticket, error was '{}'.".format(create_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as create_error:
            message = "Could not create ticket, error was '{}'.".format(create_error)
            logger.error(message)
            raise IOError(message)

    def change_requester(self, ticket_id, requester_id, comment):
        """Assign new requester to existing ticket

        :param ticket_id: ID of the ticket to assign new requester to
        :type ticket_id: int|str
        :param requester_id: ID of the user to be used as new requester fo the ticket
        :type requester_id: int|str
        :param comment: The comment of the reassignment
        :type comment: str
        :raise ValueError: If no requester or/and ticket were found or missing the comment.
        :raise IOError: If there was a communication error.
        """

        logger.info("Setting new requester with ID {} for"
                    " ticket with ID {}. Comment: '{}'".format(requester_id, ticket_id, comment))
        change_requester_comment = Comment(comment)
        try:
            self.put_uri("/securechangeworkflow/api/securechange/tickets/{}/change_requester/{}".format(ticket_id,
                                                                                                        requester_id),
                    change_requester_comment.to_xml_string(), expected_status_codes=[200, 201])
        except (REST_Not_Found_Error, REST_Bad_Request_Error) as error:
            msg = "Could not set new requester for the ticket. Error: {}".format(error)
            logger.error(msg)
            raise ValueError(msg)
        except requests.RequestException as error:
            msg = "Could not set new requester for the ticket. Error: {}.".format(error)
            logger.error(msg)
            raise IOError(msg)

    def cancel_ticket(self, ticket_id, requester_id=None):
        """Cancel a ticket

        :param ticket_id: The Id of the ticket
        :type ticket_id: str|int
        :param requester_id: The ID of the requestor (on behalf)
        :type requester_id: str|int
        """
        logger.info("Canceling ticket with ID {}".format(ticket_id))
        requester_info = ""
        if requester_id:
            requester_info = "?requester_id={}".format(requester_id)
        try:
            self.put_uri("/securechangeworkflow/api/securechange/tickets/{}/cancel{}".format(ticket_id, requester_info),
                         expected_status_codes=[200, 201])
        except REST_Not_Found_Error as error:
            message = "Could not cancel ticket, error was '{}'.".format(error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as error:
            message = "Could not cancel ticket, error was '{}'.".format(error)
            logger.error(message)
            raise IOError(message)

    def put_task(self, task):
        """Update an existing ticket task.

        :param task: The ticket task that will be updated.
        :type task: Step_Task
        :return: True.
        :rtype: bool
        :raise ValueError: If the task object with the specified ID was not found or
        if there were incorrect values in the task.
        :raise IOError: If there was a communication error.
        """
        if not isinstance(task, Step_Task):
            raise ValueError("task_obj must be a SecureChange ticket task.")
        logger.info("Updating task ID '%s' in SecureChange.", task.id)
        task_xml = task.to_xml_string().encode()
        logger.debug("Task data: '%s'", task_xml)
        ticket_id = task.get_nth_parent_node(2).id
        step_id = task.get_parent_node().id
        try:
            self.put_uri(
                    "/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}".format(ticket_id, step_id,
                                                                                                 task.id), task_xml,
                    expected_status_codes=200)
        except REST_Bad_Request_Error as update_error:
            message = "Could not update task, error was '{}'.".format(update_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as update_error:
            message = "Could not update task, error was '{}'.".format(update_error)
            logger.error(message)
            raise IOError(message)
        return True

    def put_field(self, field):
        """Update an existing ticket field.

        :param field: The step field that will be updated.
        :type field: Step_Field_*
        :Returns: True.
        :rtype: bool
        :raise ValueError: If the field object with the specified ID was not found or
        if there were incorrect values in the field.
        :raise IOError: If there was a communication error.
        """
        if not isinstance(field, Step_Field_Base):
            raise ValueError("field must be a SecureChange ticket field.")
        logger.info("Updating field ID '%s' in SecureChange.", field.id)
        field_xml = field.to_xml_string().encode()
        logger.debug("Field data: '%s'", field_xml)

        ticket_id = field.get_nth_parent_node(3).id
        step_id = field.get_nth_parent_node(2).id
        task_id = field.get_parent_node().id
        try:
            self.put_uri(
                    "/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/fields/{}".format(ticket_id,
                                                                                                           step_id,
                                                                                                           task_id,
                                                                                                           field.id),
                    field_xml, expected_status_codes=200)
        except REST_Bad_Request_Error as update_error:
            message = "Could not update field, error was '{}'.".format(update_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as update_error:
            message = "Could not update field, error was '{}'.".format(update_error)
            logger.error(message)
            raise IOError(message)
        return True

    def implement_multi_group_change(self, ticket_id, task_id=None):
        """Run Implementation of the Multi Group Change

        :param ticket_id: The Ticket ID
        :type ticket_id: int|str
        :param task_id: The Task ID
        :type task_id: int|str
        :return: MultiGroupChangeImplementResult
        """
        logger.info("Running implementation of the multi group change for ticket {}".format(ticket_id))
        if not task_id:
            ticket = self.get_ticket_by_id(ticket_id)
            task_id = ticket.get_current_task().id
        try:
            response = self.put_uri("/securechangeworkflow/api/securechange/"
                                    "tickets/{}/steps/current/tasks/{}"
                                    "/multi_group_change/implement".format(ticket_id, task_id),
                                    expected_status_codes=[200, 201]).response.content
        except (REST_Bad_Request_Error, REST_Not_Found_Error, REST_Unauthorized_Error) as error:
            message = "Could rum multi group implementation. Error: '{}'.".format(error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as error:
            message = "Could rum multi group implementation. Error: '{}'.".format(error)
            logger.error(message)
            raise IOError(message)
        return MultiGroupChangeImplementResult.from_xml_string(response)

    def get_sc_users_list(self):
        """Get the list of users currently configured in SecureChange.

        :return: List of users currently configured in SecureChange.
        :rtype: User_List
        """
        users_xml_string = self.get_uri("/securechangeworkflow/api/securechange/users",
                                        expected_status_codes=200).response.content
        users_xml_node = ET.fromstring(users_xml_string)
        users_list = User_List.from_xml_node(users_xml_node)
        return users_list

    def get_sc_user_by_id(self, user_id):
        """Get the details for the specified SecureChange user.

        :return: The SecureChange user details.
        :rtype: User
        """
        logger.debug("Getting username by ID '%s'.", user_id)

        try:
            user_xml_string = self.get_uri("/securechangeworkflow/api/securechange/users/{}".format(user_id),
                                           expected_status_codes=200).response.content
        except REST_Bad_Request_Error as error:
            message = "Could not find user with ID {}. Error: '{}'.".format(user_id, error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as error:
            message = "Could not find user with ID {}. Error: {}".format(user_id, error)
            logger.error(message)
            raise IOError(message)
        user_xml_node = ET.fromstring(user_xml_string)
        user_type = user_xml_node.tag
        if user_type == "user":
            user = User.from_xml_node(user_xml_node)
        elif user_type == "group":
            user = Group.from_xml_node(user_xml_node)
        else:
            logger.warning("The user with ID {} has unsupported type: {}".format(user_id, user_type))
            raise ValueError
        return user

    def get_user_by_username(self, username, *, exact_match=False):
        """Get SC user by username.

        :param username: The username to find in SC
        :type username: str
        :param exact_match: If it should be exact match from 16.2 (false for backward compatibility)
        :type exact_match: bool
        :rtype: User|Group
        """
        logger.debug("Getting user {}".format(username))
        exact_match_param = ""
        if exact_match:
            exact_match_param = "&exact_name=true"
        try:
            users_xml_string = self.get_uri(
                "/securechangeworkflow/api/securechange/users/?user_name={}{}".format(username, exact_match_param),
                expected_status_codes=200).response.content
            found_users = User_List.from_xml_string(users_xml_string)
        except REST_Bad_Request_Error as error:
            message = "Could not find user '{}'. Error '{}'.".format(username, error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as error:
            message = "Could not find user '{}'. Error".format(username, error)
            logger.error(message)
            raise IOError(message)
        if not User_List or len(found_users) < 1:
            msg = "No user '{}' found".format(username)
            logger.error(msg)
            raise ValueError(msg)
        elif len(found_users) > 1:
            msg = "Multiple users that have '{}' in their username are found. " \
                  "Getting the first with exact name.".format(username)
            logger.info(msg)
            found_users = [user for user in found_users if username in user.get_name_fields()]
        return found_users[0]

    def get_user_by_email(self, email):
        """Get SC user by email.

        :param email: The username to find in SC
        :type email: str
        :rtype: User|User_list
        """
        logger.debug("Getting user with email '{}'".format(email))
        try:
            users_xml_string = self.get_uri("/securechangeworkflow/api/securechange/users/?email={}".format(email),
                                            expected_status_codes=200).response.content
            found_users = User_List.from_xml_string(users_xml_string)
        except REST_Bad_Request_Error as error:
            message = "Could not find user with email '{}'. Error '{}'.".format(email, error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as error:
            message = "Could not find user with email '{}'. Error".format(email, error)
            logger.error(message)
            raise IOError(message)
        return found_users

    def get_all_members_of_group(self, group_name):
        """Get the list of members of group recursively

        :param group_name: The name of the group
        :type group_name: str
        :return: [Member]
        """
        members = []
        logger.debug("Retrieving all members of the group '{}'".format(group_name))
        group = self.get_user_by_username(group_name, exact_match=True)
        print(group)
        print(vars(group))
        if not isinstance(group, Group):
            raise ValueError("User '{}' is not of type Group".format(group_name))
        for member in group.members:
            if member.get_attribs()[Attributes.XSI_NAMESPACE_TYPE] == "user":
                members.append(member)
            elif member.get_attribs()[Attributes.XSI_NAMESPACE_TYPE] == "group":
                members.extend(self.get_all_members_of_group(member.name))
            else:
                logger.info("User '{}' is of unknown type, skipping.".format(member.name))
        return members

    def get_all_members_of_group_by_group_id(self, group_id):
        """Get the list of members of group recursively

        :param group_id: The ID of the group (user id)
        :type group_id: str|int
        :return: [Member]
        """
        members = []
        logger.debug("Retrieving all members of the group with ID '{}'".format(group_id))
        group = self.get_sc_user_by_id(group_id)
        if not isinstance(group, Group):
            raise ValueError("User with ID '{}' is not of type Group".format(group_id))
        for member in group.members:
            if member.get_attribs()[Attributes.XSI_NAMESPACE_TYPE] == "user":
                members.append(member)
            elif member.get_attribs()[Attributes.XSI_NAMESPACE_TYPE] == "group":
                members.extend(self.get_all_members_of_group_by_group_id(member.id))
            else:
                logger.info("User '{}' is of unknown type, skipping.".format(member.name))
        return members

    def import_user_from_ldap(self, username, managed_locally=None, ldap_configuration=None):
        logger.debug("Importing user {} from LDAP.")
        user_to_import = User.instantiate_ldap_user_object(username, managed_locally, ldap_configuration)
        user_to_import_xml = user_to_import.to_xml_string().encode()
        logger.debug("User XML:\n {}".format(user_to_import_xml))
        try:
            response = self.post_uri("/securechangeworkflow/api/securechange/users/", user_to_import_xml,
                                     expected_status_codes=201)
            user_id = response.get_created_item_id()
            return user_id
        except REST_Bad_Request_Error as create_error:
            message = "Could not import user {}, error was '{}'.".format(username, create_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as create_error:
            message = "Could not import user {}, error was '{}'.".format(username, create_error)
            logger.error(message)
            raise IOError(message)

    def get_ticket_ids_by_status(self, status):
        url = "/securechangeworkflow/api/securechange/tickets?status={}".format(status)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Failed to find tickets with status '{}'".format(status)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException:
            message = "Failed to GET tickets with status '{}'.".format(status)
            logger.error(message)
            raise IOError(message)
        xml_node = ET.fromstring(response_string)
        return TicketList.from_xml_node(xml_node)

    def reassign_task(self, task_obj, user_id, reassign_message):
        """Reassign Ticket Task to other user by his ID

        :param task_obj: Object of Task
        :type task_obj: Step_Task
        :param user_id: ID of the user to assign ticket to
        :type user_id: int
        :param reassign_message: The reason of reassignment
        :type reassign_message: str
        """
        if not isinstance(task_obj, Step_Task):
            raise ValueError("task_obj must be a SecureChange ticket task.")
        logger.debug("Re-Assigning Task to user %s.", user_id)
        logger.debug("Task data: '%s'", task_obj.to_xml_string().encode())
        ticket_id = task_obj.get_nth_parent_node(2).id
        step_id = task_obj.get_parent_node().id
        reassign_message = Reassign_Comment(reassign_message)
        try:
            self.put_uri(
                    "/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/reassign/{}".format(ticket_id,
                                                                                                             step_id,
                                                                                                             task_obj.id,
                                                                                                             user_id),
                    reassign_message.to_xml_string(), expected_status_codes=200)
        except REST_Bad_Request_Error as update_error:
            message = "Could not re-assign task, error was '{}'.".format(update_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as update_error:
            message = "Could not re-assign task, error was '{}'.".format(update_error)
            logger.error(message)
            raise IOError(message)
        else:
            user = self.get_sc_user_by_id(user_id)
            task_obj.assignee = user.name
            task_obj.assignee_id = user_id
            task_obj.status = Elements.ASSIGNED
            return task_obj

    def reassign_task_by_username(self, task_obj, username, reassign_message):
        """Reassign a ticket task to another user by their username.

        :param task_obj: Object of Task
        :type task_obj: Step_Task
        :param username: Name of the user
        :type username: str
        :param reassign_message: The reason of reassignment
        :type reassign_message: str
        """
        try:
            user = self.get_sc_user(username)
            user_id = user.id
        except ValueError as error:
            message = "Couldn't re-assign task, as user was not found. Error: {}".format(error)
            logger.error(message)
            raise ValueError(message)
        else:
            return self.reassign_task(task_obj, user_id, reassign_message)

    def redo_step(self, from_task, to_step_id, redo_message):
        """Redo a ticket step.

        :param from_task: Object of Task
        :type from_task: Step_Task
        :param to_step_id: ID of the step to redo
        :type to_step_id: int
        :param redo_message: The reason for the redo.
        :type redo_message: str
        """
        if not isinstance(from_task, Step_Task):
            raise ValueError("from_task must be a SecureChange ticket task.")
        logger.debug("Redoing ticket step ID '%s'.", to_step_id)
        ticket_id = from_task.get_nth_parent_node(2).id
        step_id = from_task.get_parent_node().id
        reassign_message = Redo_Comment(redo_message)
        try:
            self.put_uri("/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/redo/{}".format(ticket_id,
                                                                                                              step_id,
                                                                                                              from_task.id,
                                                                                                              to_step_id),
                    reassign_message.to_xml_string(), expected_status_codes=200)
        except REST_Bad_Request_Error as update_error:
            message = "Could not redo step, error was '{}'.".format(update_error)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException as update_error:
            message = "Could not redo step, error was '{}'.".format(update_error)
            logger.error(message)
            raise IOError(message)

    def get_verifier_results(self, ticket_id, step_id, task_id, request_id):
        """Get verifier results for an access request field.

        :type request_id: int
        :type task_id: int
        :type step_id: int
        :type ticket_id: int
        :param ticket_id: The ID of the ticket containing the access request field.
        :param step_id: The ID of the step containing the access request field.
        :param task_id: The ID of the task containing the access request field.
        :param request_id: The ID of the access request field.
        :return:
        """
        url = "/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/multi_access_request/{}/verifier"
        format_url = url.format(ticket_id, step_id, task_id, request_id)
        try:
            response_string = self.get_uri(format_url, expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Failed to find verifier for ticket id '{}'".format(ticket_id)
            logger.error(message)
            raise ValueError(message)
        except requests.RequestException:
            message = "Failed to GET verifier results for ticket ID '{}'.".format(ticket_id)
            logger.error(message)
            raise IOError(message)
        xml_node = ET.fromstring(response_string)
        return AccessRequestVerifierResult.from_xml_node(xml_node)


class Access_Request_Generator:
    """This class is used to generate a SecureChange Access_Request from strings.

    :cvar IPV4_ADDRESS: The string used to identify an IP address.
    :cvar IPV4_ADDRESS_RANGE: The string used to identify an IP address range.
    :cvar IPV4_ADDRESS_WITH_MASK: The string used to identify an IP address with a subnet mask.
    :cvar ANY: The string used to identify a generic 'any' network object.
    :cvar PROTOCOL: The string used to identify a network protocol.
    :cvar HOSTNAME_PLACEHOLDER: The string that is used as a place holder in the parsed CSV file.
    """
    ANY = "ANY"
    INTERNET = "INTERNET"
    DNS = "DNS"
    ICMP = "ICMP"
    OBJECT = "OBJECT"
    IP = "IP"
    IPV4_ADDRESS = "IPV4"
    IPV4_ADDRESS_RANGE = "IPV4_RANGE"
    IPV4_ADDRESS_WITH_MASK = "IPV4_WITH_MASK"
    IPV6_ADDRESS = "IPV6"
    IPV6_ADDRESS_RANGE = "IPV6_RANGE"
    IPV6_ADDRESS_WITH_MASK = "IPV6_WITH_MASK"
    OTHER = "OTHER"
    PREDEFINED = "PREDEFINED"
    PROTOCOL = "PROTOCOL"
    HOSTNAME_PLACEHOLDER = "$hostname"

    def __init__(self, rules):
        for rule in rules:
            self.predefined_services = get_iana_services()
            rule["sources"] = self._prepare_targets(rule["sources"])
            rule["destinations"] = self._prepare_targets(rule["destinations"])
            services = []
            services.extend(rule["services"])
            normalized_services = self._services_to_ports(services)
            rule["services"] = self._prepare_services(normalized_services)
        self.rules = rules

    @classmethod
    def from_csv_file(cls, csv_file_path, hostname, hostname_placeholder=HOSTNAME_PLACEHOLDER):
        """Constructor

        :param hostname_placeholder: The placeholder string for the hostname in the CSV file.
        :param csv_file_path: The path to the CSV template file.
        :type csv_file_path: str
        :param hostname: The hostname that will be used to replace the hostname placeholder in the CSV template file.
        :type hostname: str
        """
        separator_char = "|"
        rules = []
        csv_lines = get_csv_parser(csv_file_path)
        for index, line in enumerate(csv_lines):
            logger.debug("Handling line number %s:%s", index, line)
            try:
                targets = [target.strip() for target in line[0].split(separator_char)]
                raw_sources = [source.strip().replace(hostname_placeholder, hostname) for source in
                               line[1].split(separator_char)]
                raw_destinations = [destination.strip().replace(hostname_placeholder, hostname) for destination in
                                    line[2].split(separator_char)]
                raw_services = [service.strip() for service in line[3].split(separator_char)]
                action = line[4].strip()
                comment = line[5].strip().replace(hostname_placeholder, hostname)
                rules.append({"targets": targets, "sources": raw_sources, "destinations": raw_destinations,
                              "services": raw_services, "action": action, "comment": comment})
            except IndexError:
                logger.error("Error parsing line number %s.", index)
                continue
        logger.debug("Rules are %s", rules)
        return Access_Request_Generator(rules)

    @classmethod
    def from_list_of_tuples(cls, rule_tuples):
        """Constructor

        :param rule_tuples: The list of tuples, where each tuple consists of (targets,sources,destinations,services,
        action,comment).
            targets is a list,where each element can either be a device name or "ANY"
            sources and destinations are lists, where each element can be one of the following:
                1. IPv4/6 networks.
                2. IPv4/6 range.
                3. IPv4/6 address.
                4. "ANY" - signifying any target.
            services is a list, where each element can be one of the following:
                1. TCP/UDP and port number (e.g. "TCP 80" or "UDP 161") (If only the port number is specified,
                TCP protocol is assumed.)
                2. ICMP/ping for ICMP echo.
                3. "ANY" - for any service.
            action can be one of the following:
                1. "allow"/"accept" - To allow the traffic.
                2. "block"/"drop"/"deny"/"reject" - To drop the traffic.
                3. "remove" - To remove the specified rule.
        :type rule_tuples: list[tuple[list[str],list[str],list[str],list[str],str,str]
        """
        rules = []
        for rule_tuple in rule_tuples:
            targets = rule_tuple[0]
            raw_sources = [source.strip() for source in rule_tuple[1] if source]
            raw_destinations = [destination.strip() for destination in rule_tuple[2] if destination]
            raw_services = [service.strip() for service in rule_tuple[3] if service]
            action = rule_tuple[4].strip()
            comment = rule_tuple[5]
            if comment:
                comment = rule_tuple[5].strip()
            rules.append({"targets": targets, "sources": raw_sources, "destinations": raw_destinations,
                          "services": raw_services, "action": action, "comment": comment})
        return Access_Request_Generator(rules)

    @staticmethod
    def _create_ar_target(target, target_type):
        logger.debug("Handling target '%s'.", target)
        target_types_dict = {Access_Request_Generator.DNS: DNS_Access_Request_Target,
                             Access_Request_Generator.IPV4_ADDRESS: IP_Access_Request_Target,
                             Access_Request_Generator.IPV4_ADDRESS_WITH_MASK: IP_Access_Request_Target,
                             Access_Request_Generator.IPV4_ADDRESS_RANGE: IP_Range_Access_Request_Target,
                             Access_Request_Generator.IPV6_ADDRESS: IP_Access_Request_Target,
                             Access_Request_Generator.IPV6_ADDRESS_WITH_MASK: IP_Access_Request_Target,
                             Access_Request_Generator.IPV6_ADDRESS_RANGE: IP_Range_Access_Request_Target,
                             Access_Request_Generator.ANY: Any_Access_Request_Target,
                             Access_Request_Generator.INTERNET: Internet_Access_Request_Target,
                             Access_Request_Generator.OBJECT: Object_Access_Request_Target}
        if target_type == "source":
            target_tag = Elements.SOURCE
        elif target_type == "destination":
            target_tag = Elements.DESTINATION
        else:
            raise ValueError("Target type must be either 'source' or 'destination'.")

        if target["type"] == Access_Request_Generator.DNS:
            ar_target = target_types_dict[target["type"]](target_tag, None, None, target["address"], None)
        elif target["type"] in [Access_Request_Generator.IPV4_ADDRESS, Access_Request_Generator.IPV4_ADDRESS_WITH_MASK,
                                Access_Request_Generator.IPV6_ADDRESS, Access_Request_Generator.IPV6_ADDRESS_WITH_MASK]:
            ar_target = target_types_dict[target["type"]](target_tag, None, target["address"], target.get("netmask"),
                                                          None)
        elif target["type"] in [Access_Request_Generator.IPV4_ADDRESS_RANGE,
                                Access_Request_Generator.IPV6_ADDRESS_RANGE]:
            range_first_ip = target["address"].split("-")[0]
            range_last_ip = target["address"].split("-")[1]
            ar_target = target_types_dict[target["type"]](target_tag, None, range_first_ip, range_last_ip, None)
        elif target["type"] in [Access_Request_Generator.ANY, Access_Request_Generator.INTERNET]:
            ar_target = target_types_dict[target["type"]](target_tag, None, None)
        elif target["type"] == Access_Request_Generator.OBJECT:
            ar_target = target_types_dict[target["type"]](target_tag, None, target["address"], None, None,
                                                          target.get("netmask"), None, None, None)
        else:
            raise ValueError("Unknown target type {}".format(target["type"]))
        return ar_target

    def create_multi_access_requests(self):
        """Create the Access_Request object.

        :return: The generated Access_Request object.
        :rtype: Access_Request
        """
        allow_keywords = ["allow", "accept"]
        drop_keywords = ["block", "drop", "deny", "reject"]
        remove_keywords = ["remove"]
        access_requests = []
        for index, rule in enumerate(self.rules):
            targets = []
            sources = []
            destinations = []
            services = []
            order = "AR" + str(index + 1)
            logger.debug("Handling rule %s", rule)
            if not rule["action"] or rule["action"].lower() in allow_keywords:
                rule["action"] = "Accept"
            elif rule["action"].lower() in drop_keywords:
                rule["action"] = "Drop"
            elif rule["action"].lower() in remove_keywords:
                rule["action"] = "Remove"
            else:
                raise ValueError("Unknown action {}".format(rule["action"]))

            for target in rule["targets"]:
                if target is None or target.upper() == Access_Request_Generator.ANY:
                    targets.append(Any_Access_Request_Device())
                    break
                else:
                    targets.append(Named_Access_Request_Device(None, None, None, None, target, None))

            if isinstance(rule["sources"], list):
                sources = [self._create_ar_target(source, "source") for source in rule["sources"]]
            else:
                sources.append(self._create_ar_target(rule["sources"], "source"))

            if isinstance(rule["destinations"], list):
                destinations = [self._create_ar_target(destination, "destination") for destination in
                                rule["destinations"]]
            else:
                destinations.append(self._create_ar_target(rule["destinations"], "destination"))

            for service in rule["services"]:
                if service["type"] == Access_Request_Generator.ANY:
                    services = [Any_Service_Target()]
                    break
                elif service["type"] == Access_Request_Generator.PROTOCOL:
                    service = Protocol_Service_Target(None, service["port"], service["protocol"], None)
                elif service["type"] == Access_Request_Generator.ICMP:
                    service = Predefined_Service_Target(None, xml_tags.TYPE_OTHER, 1, "icmp-proto")
                elif service["type"] == Access_Request_Generator.PREDEFINED:
                    logger.warn("Unknown predefined type '%s', skipping.", service)
                    continue
                services.append(service)
            access_request = Access_Request(order, targets, None, copy.deepcopy(sources), copy.deepcopy(destinations),
                                            copy.deepcopy(services), None, rule["action"], rule["comment"], [], None,
                                            None, None)
            logger.debug("Generated access request: %s", access_request.to_xml_string())
            access_requests.append(access_request)
        return access_requests

    def _services_to_ports(self, services):
        normalized_services = []
        for service in services:
            if service.lower().startswith(UDP):
                valid_protocols = (UDP,)
                defined_service = service[3:].strip()
            elif service.lower().startswith(TCP):
                valid_protocols = (TCP,)
                defined_service = service[3:].strip()
            else:
                defined_service = service
                valid_protocols = (UDP, TCP)
            service_to_port = self.predefined_services.get(defined_service)
            if service_to_port:
                found_services = ["{} {}".format(s[0], s[1]) for s in service_to_port if s[0] in valid_protocols]
                normalized_services.extend(found_services)
            else:
                normalized_services.append(service)
        return normalized_services

    @staticmethod
    def normalize_ipv4_network_mask(network_mask):
        """If the network mask is in CIDR notation, convert it to quad dotted notation.

        :param network_mask: The network mask that will be processed.
        :type network_mask: str
        :return: The network mask in quad dotted notation.
        :rtype: str
        """
        logger.debug("Normalizing network mask: '%s'", network_mask)
        if len(network_mask) <= 2:
            network_mask = calculate_quad_dotted_netmask(int(network_mask))
        return network_mask

    def _detect_service_type(self, service_string):
        """Determine if the specified service is a SecureTrack service in the form of PROTOCOL PORT_NUMBER.

        :param service_string: The service string to be processed.
        :type service_string: str
        """
        service_string = service_string.lower().strip()
        tcp_udp_service_regex = r"(tcp|udp).*(<|>)?.*[0-9]+( ?- ?[0-9]+)?|[0-9]+( ?- ?[0-9]+)?.*(<|>)?.*(tcp|udp)"
        icmp_service_regex = r".*icmp|ping.*"
        port_number_only_regex = r"[1-9](?:[0-9]*)?( ?- ?[1-9](?:[0-9]*))?$"
        logger.debug("Trying to match service string %s", service_string)
        if re.match(tcp_udp_service_regex, service_string) or re.match(port_number_only_regex, service_string):
            logger.debug("Service string matches TCP/UDP regex.")
            return Access_Request_Generator.PROTOCOL
        elif re.match(icmp_service_regex, service_string):
            logger.debug("Service string matches ICMP regex.")
            return Access_Request_Generator.ICMP
        elif service_string in ["any", "all"]:
            logger.debug("Service string matches %s", Access_Request_Generator.ANY)
            return Access_Request_Generator.ANY
        else:
            iana_service = self.predefined_services.get(service_string)
            if iana_service is not None:
                return Access_Request_Generator.PREDEFINED
            else:
                message = "Unable to detect service type for '{}'".format(service_string)
                logger.critical(message)
                raise ValueError(message)

    @staticmethod
    def _split_service_protocol_and_port(service_string, default_protocol="TCP"):
        """Separate the protocol and port number from the service string.

        :param service_string: The service string to be processed.
        :type service_string: str
        """
        logger.debug("Got the following protocol and port to split: '%s'", service_string)
        split_service_string = service_string.lower().split(" ")
        try:
            protocol = split_service_string[0]
            port = split_service_string[1]
        except IndexError:
            port_first_regex = r"([0-9]+(\s?-\s?[0-9]+)?)([udp|tcp])"
            protocol_first_regex = r"([udp|tcp])([0-9]+(\s?-\s?[0-9]+)?)"
            port_only_regex = r"([0-9]+)( ?- ?[0-9]+)?"
            port_first_regex_match = re.match(port_first_regex, service_string)
            protocol_first_regex_match = re.match(protocol_first_regex, service_string)
            port_only_regex_match = re.match(port_only_regex, service_string)
            if port_first_regex_match:
                port = port_first_regex_match.group(1)
                protocol = port_first_regex_match.group(2)
            elif protocol_first_regex_match:
                protocol = protocol_first_regex_match.group(1)
                port = protocol_first_regex_match.group(2)
            elif port_only_regex_match:
                protocol = default_protocol
                port = port_only_regex_match.group(1)
            else:
                raise ValueError("Could not match protocol and port of service {}.".format(service_string))
        if port == "0":
            port = "1-65535"
        protocol = protocol.upper()
        logger.debug("Returning the protocol %s and port %s", protocol, port)
        return protocol, port

    @staticmethod
    def _split_ipv4_ip_and_netmask(network_object_string):
        """Separate the IP and netmask from the network object string.

        :param network_object_string: The network object string to be processed.
        :type network_object_string: str
        :return: IP address, network mask
        """
        logger.debug("Splitting netmask for IPv4 string %s", network_object_string)
        ip_address = network_object_string.split("/")[0]
        network_mask = Access_Request_Generator.normalize_ipv4_network_mask(network_object_string.split("/")[1])
        return ip_address, network_mask

    @staticmethod
    def _split_ipv6_ip_and_netmask(network_object_string):
        """Separate the IP and netmask from the network object string.

        :param network_object_string: The network object string to be processed.
        :type network_object_string: str
        :return: IP address, network mask
        """
        logger.debug("Splitting netmask for IPv6 string %s", network_object_string)
        ip_address = network_object_string.split("/")[0]
        network_mask = network_object_string.split("/")[1]
        return ip_address, network_mask

    @staticmethod
    def _detect_network_object_type(network_object_string):
        """Determine whether the specified network object string is an IP, an IP range, IP with netmask,
        Hostname or the string "ANY".

        :param network_object_string: The network object string to be processed.
        :type network_object_string: str
        :return: The type of the network object string.
        :rtype: str
        """
        # The network object string contains a network mask
        logger.debug("Detecting network object type for string %s", network_object_string)
        any_type_strings = [Access_Request_Generator.ANY, "0.0.0.0", "0.0.0.0/0"]
        internet_type_strings = [Access_Request_Generator.INTERNET]
        ipv4_address_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|/\d{1,2})?"
        ipv4_address_range_regex = "{}-{}".format(ipv4_address_regex, ipv4_address_regex)
        # noinspection PyPep8
        ipv6_address_regex = r'(?:::|(?:(?:[a-fA-F0-9]{1,4}):){7}(?:(?:[a-fA-F0-9]{1,4}))|(?::(?::(?:[a-fA-F0-9]{1,' \
                             r'4})){1,6})|(?:(?:(?:[a-fA-F0-9]{1,4}):){1,6}:)|(?:(?:(?:[a-fA-F0-9]{1,4}):)(?::(?:[' \
                             r'a-fA-F0-9]{1,4})){1,6})|(?:(?:(?:[a-fA-F0-9]{1,4}):){2}(?::(?:[a-fA-F0-9]{1,4})){1,' \
                             r'5})|(?:(?:(?:[a-fA-F0-9]{1,4}):){3}(?::(?:[a-fA-F0-9]{1,4})){1,4})|(?:(?:(?:[' \
                             r'a-fA-F0-9]{1,4}):){4}(?::(?:[a-fA-F0-9]{1,4})){1,3})|(?:(?:(?:[a-fA-F0-9]{1,' \
                             r'4}):){5}(?::(?:[a-fA-F0-9]{1,4})){1,2}))(?:/[0-9]+)?'
        ipv6_address_range_regex = "{}-{}".format(ipv6_address_regex, ipv6_address_regex)
        if network_object_string.upper() in any_type_strings:
            object_type = Access_Request_Generator.ANY
        elif network_object_string in internet_type_strings:
            object_type = Access_Request_Generator.INTERNET
        elif re.match(ipv4_address_range_regex, str(network_object_string)) is not None:
            object_type = Access_Request_Generator.IPV4_ADDRESS_RANGE
        elif re.match(ipv6_address_range_regex, str(network_object_string)) is not None:
            object_type = Access_Request_Generator.IPV6_ADDRESS_RANGE
        # The network object string is an IP address without a mask.
        elif re.match(ipv4_address_regex, str(network_object_string)) is not None:
            if "/" in network_object_string:
                object_type = Access_Request_Generator.IPV4_ADDRESS_WITH_MASK
            else:
                object_type = Access_Request_Generator.IPV4_ADDRESS
        elif re.match(ipv6_address_regex, str(network_object_string)) is not None:
            if "/" in network_object_string:
                object_type = Access_Request_Generator.IPV6_ADDRESS_WITH_MASK
            else:
                object_type = Access_Request_Generator.IPV6_ADDRESS
        # The network object string is a hostname.
        elif "/" in network_object_string:
            object_type = Access_Request_Generator.OBJECT
        else:
            object_type = Access_Request_Generator.DNS
        logger.debug("Detected type is '%s'.", object_type)
        return object_type

    def _prepare_targets(self, raw_targets):
        targets = []
        for raw_target in raw_targets:
            logger.debug("Preparing raw target '%s'.", raw_target)
            target_type = self._detect_network_object_type(raw_target)
            if target_type == Access_Request_Generator.IPV4_ADDRESS_WITH_MASK:
                address, netmask = self._split_ipv4_ip_and_netmask(raw_target)
            elif target_type == Access_Request_Generator.IPV6_ADDRESS_WITH_MASK:
                address, netmask = self._split_ipv4_ip_and_netmask(raw_target)
            elif target_type == Access_Request_Generator.IPV4_ADDRESS:
                address, netmask = raw_target, "255.255.255.255"
            elif target_type in [Access_Request_Generator.IPV4_ADDRESS_RANGE,
                                 Access_Request_Generator.IPV6_ADDRESS_RANGE, Access_Request_Generator.DNS,
                                 Access_Request_Generator.IPV6_ADDRESS]:
                address, netmask = raw_target, None
            elif target_type in [Access_Request_Generator.ANY, Access_Request_Generator.INTERNET]:
                address, netmask = None, None
            elif target_type == Access_Request_Generator.OBJECT:
                address, netmask = raw_target.split("/")
            else:
                raise ValueError("Unknown target type '{}'".format(target_type))
            targets.append({"address": address, "netmask": netmask, "type": target_type})
        return targets

    def _prepare_services(self, raw_services):
        services = []
        for raw_service in raw_services:
            service_type = self._detect_service_type(raw_service)
            if service_type == Access_Request_Generator.PROTOCOL:
                protocol, port = self._split_service_protocol_and_port(raw_service)
                service = {"type": service_type, "protocol": protocol, "port": port}
            elif service_type == Access_Request_Generator.PREDEFINED:
                service = self.predefined_services.get(raw_service.lower())
                try:
                    protocol, port = service[0][0], service[0][1]
                except TypeError:
                    continue
                else:
                    service = {"type": Access_Request_Generator.PROTOCOL, "protocol": protocol, "port": port}
            elif service_type in [Access_Request_Generator.ICMP, Access_Request_Generator.ANY]:
                service = {"type": service_type}
            else:
                raise ValueError("Unknown service type.")
            services.append(service)
        return services


class Step_Task_Field_Copier:
    """
    This class is used to copy fields between two step tasks.
    """

    def __init__(self, sc_helper, source_task, destination_task, ignore_missing_fields=False,
                 skip_fields_with_value=False, ignore_errors=False):
        """
        :param sc_helper: The Secure_Change_Helper that is connected to the destination SC system.
        :type sc_helper: Secure_Change_Helper
        :param source_task: The task containing the fields that will be copied to the destination task.
        :type source_task: Step_Task
        :param destination_task: The task to which the fields will be copied.
        :type destination_task: Step_Task
        :param ignore_missing_fields: If set to True, fields that exist in the source task but not in
        the destination task will be ignored.
        Otherwise, a ValueError exception will be thrown.
        :type ignore_missing_fields: bool
        :param skip_fields_with_value: If set to True, fields in the destination task that already have a value will
        be skipped.
        :type skip_fields_with_value: bool
        """
        self.sc_helper = sc_helper
        self.source_task = source_task
        self.destination_task = destination_task
        self.ignore_missing_fields = ignore_missing_fields
        self.skip_fields_with_value = skip_fields_with_value
        self.ignore_errors = ignore_errors

    def copy_fields(self, submit_fields=True):
        handled_destination_fields = []
        destination_fields = []
        while self.source_task.fields:
            source_field = self.source_task.fields.pop()
            destination_field = None
            candidate_fields = self.destination_task.get_field_list_by_name_and_type(source_field.name,
                                                                                     source_field.get_field_type())
            for candidate_field in candidate_fields:
                if candidate_field not in handled_destination_fields:
                    logger.debug("Found matching field '%s'.", candidate_field)
                    destination_field = candidate_field
                    handled_destination_fields.append(destination_field)
                    break
            if destination_field is not None:
                if self.skip_fields_with_value and destination_field.get_field_value():
                    logger.info("Skipping destination field '%s' with value '%s'.", destination_field,
                                destination_field.get_field_value())
                    continue
                destination_field.set_field_value(source_field.get_field_value())
                destination_fields.append(destination_field)
            else:
                if self.ignore_missing_fields:
                    logger.info("Skipping missing field with name '%s'.", source_field.name)
                else:
                    message = "Could not find field with name '{}' and type '{}' in destination task.".format(
                            source_field.name, type(source_field))
                    logger.critical(message)
                    raise ValueError(message)
        if submit_fields:
            for destination_field in destination_fields:
                try:
                    self.sc_helper.put_field(destination_field)
                except (ValueError, IOError) as error:
                    if not self.ignore_errors:
                        raise error
                    else:
                        logger.warn("Ignoring error '%s'.", error)


class Secure_Change_API_Handler:
    """
    This class is used to register functions in scripts to be triggered via the SecureChange API hook system.
    Actions can be registered for a step name or index,ticket status and trigger action.
    """
    CREATE = "CREATE"
    CLOSE = "CLOSE"
    CANCEL = "CANCEL"
    REJECT = "REJECT"
    ADVANCE = "ADVANCE"
    REDO = "REDO"
    RESUBMIT = "RESUBMIT"
    REOPEN = "REOPEN"
    TRIGGER_ACTIONS = (CREATE, CLOSE, CANCEL, REJECT, ADVANCE, REDO, RESUBMIT, REOPEN)

    def __init__(self, ticket, ticket_info=None):
        """
        :param ticket: The ticket that actions will be triggered for.
        :type ticket: Ticket
        :param ticket_info: The info about the ticket we get from SC API trigger.
        :type ticket_info: Ticket_Info
        """
        self.ticket = ticket
        self.ticket_info = ticket_info
        self.steps = {}
        self.stages = {}
        self.completion_steps = {}
        self.statuses = {}
        self.indexes = {}
        self.actions = {}

    def _register_items(self, dict_name, items, func, args, kwargs):
        item_dict = getattr(self, dict_name)
        if item_dict is not None:
            if isinstance(items, (list, tuple)):
                for item in items:
                    item_dict[item] = func, args, kwargs
            else:
                item_dict[items] = func, args, kwargs
        else:
            raise ValueError("No attribute with the name '{}'.".format(dict_name))

    def register_step(self, step_name, func, *args, **kwargs):
        """
        :param step_name: The name of the step that the function will be triggered for.
        :type  step_name: str|list[str]|tuple[str]
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        self._register_items("steps", step_name, func, args, kwargs)

    def register_status(self, status, func, *args, **kwargs):
        """
        :param status: The status of the step that the function will be triggered for.
        :type  status: str|list[str]|tuple[str]
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        self._register_items("statuses", status, func, args, kwargs)

    def register_index(self, index, func, *args, **kwargs):
        """
        :param index: The index of the step that the function will be triggered for.
        :type  index: int|list[int]|tuple[int]
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        self._register_items("indexes", index, func, args, kwargs)

    def register_action(self, action, func, *args, **kwargs):
        """
        :param action: The trigger action that the function will be triggered for.
        :type  action: str
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        if action not in Secure_Change_API_Handler.TRIGGER_ACTIONS:
            raise ValueError("Unknown trigger action '{}'.".format(action))
        self._register_items("actions", action, func, args, kwargs)

    def register_previous_step(self, stage_name, func, *args, **kwargs):
        """
        :param stage_name: The name of the stage that the function will be triggered for.
        :type  stage_name: str|list[str]|tuple[str]
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        self._register_items("stages", stage_name, func, args, kwargs)

    def register_completion_step(self, step_name, func, *args, **kwargs):
        """
        :param step_name: the completion step the function will be triggered for
        :type step_name: str|list[str]|tuple[str]
        :param func: The function that will be called.
        :type func: types.FunctionType|types.BuiltinFunctionType|types.MethodType|
        types.BuiltinMethodType|types.UnboundMethodType
        :param args: The arguments for the function that will be called.
        :param kwargs: The keyword arguments for the function that will be called.
        """
        self._register_items("completion_steps", step_name, func, args, kwargs)

    def run(self):
        logger.info("Running for ticket with ID '%s'.", self.ticket.id)
        try:
            stage_name = self.ticket_info.current_stage_name
        except (AttributeError, KeyError):
            pass
        else:
            self._run_stage(stage_name)
        try:
            completion_step_name = self.ticket_info.completion_step_name
        except AttributeError:
            pass
        else:
            self._run_completion_steps(completion_step_name)
        try:
            current_step = self.ticket.get_current_step()
        except KeyError:
            self._run_status()
            self._run_action()
        else:
            self._run_status()
            self._run_action()
            self._run_step(current_step.name)
            self._run_index(self.ticket.step_index(current_step))

    @staticmethod
    def _get_trigger_action():
        return os.environ.get("SCW_EVENT")

    def _call_func(self, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception as call_error:
            print("An error occurred while executing the function '{}' for ticket ID '{}'. Please check the logs for a "
                  "full "
                  "traceback.".format(func.__name__, self.ticket.id))
            logger.error("Got the following error while executing the function '%s' for ticket ID '%s': "
                         "'%s'.\nTraceback is '%s'.", func.__name__, self.ticket.id, call_error, traceback.format_exc())
            sys.exit(1)

    def _run_status(self):
        logger.info("Ticket ID '%s' status is '%s'.", self.ticket.id, self.ticket.status)
        try:
            func, args, kwargs = self.statuses[self.ticket.status]
        except KeyError:
            logger.debug("No function registered for status '%s'.", self.ticket.status)
        else:
            logger.info("Calling function '%s'.", func.__name__)
            self._call_func(func, *args, **kwargs)

    def _run_step(self, current_step_name):
        logger.info("Ticket ID '%s' current step name is '%s'.", self.ticket.id, current_step_name)
        try:
            func, args, kwargs = self.steps[current_step_name]
        except KeyError:
            logger.debug("No function registered for step name '%s'.", current_step_name)
        else:
            self._call_func(func, *args, **kwargs)

    def _run_index(self, current_step_index):
        logger.info("Ticket ID '%s' current step index is '%s'.", self.ticket.id, current_step_index)
        try:
            func, args, kwargs = self.indexes[current_step_index]
        except KeyError:
            logger.debug("No function registered for step index '%s'.", current_step_index)
        else:
            self._call_func(func, *args, **kwargs)

    def _run_action(self):
        action = self._get_trigger_action()
        if action:
            logger.info("Trigger action for Ticket ID '%s' is '%s'.", self.ticket.id, action)
            try:
                func, args, kwargs = self.actions[action]
            except KeyError:
                logger.debug("No function registered for trigger action '%s'.", action)
            else:
                self._call_func(func, *args, **kwargs)

    def _run_stage(self, stage_name):
        logger.info("Ticket ID '%s' was triggered from step '%s'", self.ticket.id, stage_name)
        try:
            func, args, kwargs = self.stages[stage_name]
        except KeyError:
            logger.debug("No function registered for stage name '%s'.", stage_name)
        else:
            self._call_func(func, *args, **kwargs)

    def _run_completion_steps(self, completion_step_name):
        logger.info("Ticket with ID {} was triggered from by completion step '{}'".format(self.ticket.id,
                                                                                          completion_step_name))
        try:
            func, args, kwargs = self.completion_steps[completion_step_name]
        except KeyError:
            logger.debug("No function registered for completion step {}".format(completion_step_name))
        else:
            self._call_func(func, *args, **kwargs)
