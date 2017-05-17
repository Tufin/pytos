#!/opt/tufin/securitysuite/ps/python/bin/python3.4
import os
import unittest
from unittest.mock import patch
import sys

from pytos.common.definitions import xml_tags
from pytos.securechange.helpers import Secure_Change_Helper
from pytos.securechange.xml_objects.rest import Ticket, Ticket_History_Activities, User, TicketList, User_List, Group


def fake_request_response(rest_file):
    full_path = os.path.dirname(os.path.abspath(__file__))
    sub_resources_dir = sys._getframe(1).f_locals['self'].__class__.__name__.lower()
    resource_file = os.path.join(full_path, "resources", sub_resources_dir, "{}.xml".format(rest_file))
    with open(resource_file, mode='rb') as f:
        return f.read()


class TestSecureChangeHelper(unittest.TestCase):
    def setUp(self):
        self.ticket_id = 445
        self.user_id = 11
        self.helper = Secure_Change_Helper("localhost", ("username", "password"))
        self.patcher = patch('pytos.common.rest_requests.requests.Session.send')
        self.mock_get_uri = self.patcher.start()
        self.mock_get_uri.return_value.status_code = 200

    def tearDown(self):
        self.patcher.stop()

    def test_01_post_ticket(self):
        self.mock_get_uri.return_value.headers = {'location': '1'}
        self.mock_get_uri.return_value.status_code = 201
        full_path = os.path.dirname(os.path.abspath(__file__))
        sub_resources_dir = sys._getframe(1).f_locals['self'].__class__.__name__.lower()
        resource_file = os.path.join(full_path, "resources", sub_resources_dir, "{}.xml".format('new_ticket'))
        ticket_obj = self.helper.read_ticket_template(resource_file)
        with patch('pytos.common.rest_requests.requests.Request') as mock_post_uri:
            ticket_id = self.helper.post_ticket(ticket_obj)
            mock_post_uri.assert_called_with(
                'POST',
                'https://localhost/securechangeworkflow/api/securechange/tickets/',
                auth=('username', 'password'),
                data=ticket_obj.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertEqual(ticket_id, 1)

    def test_02_get_ticket(self):
        self.mock_get_uri.return_value.content = fake_request_response("ticket")
        ticket = self.helper.get_ticket_by_id(self.ticket_id)
        self.assertIsInstance(ticket, Ticket)

    def test_03_redo_step(self):
        self.mock_get_uri.return_value.content = fake_request_response("ticket")
        ticket = self.helper.get_ticket_by_id(self.ticket_id)
        step_task_obj = ticket.get_current_task()
        target_task_id = ticket.get_previous_step()
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.redo_step(step_task_obj, target_task_id, 'Redoing step')
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/redo/{}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, ticket.get_current_step().id, step_task_obj.id, target_task_id),
                auth=('username', 'password'),
                data='<redo_step_comment>\n  <comment>Redoing step</comment>\n</redo_step_comment>',
                headers={'Content-Type': 'application/xml'}
            )

    def test_04_get_ticket_history_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("ticket_history_activities")
        ticket_history = self.helper.get_ticket_history_by_id(self.ticket_id)
        self.assertIsInstance(ticket_history, Ticket_History_Activities)

    def test_05_get_sc_user_by_id(self):
        self.mock_get_uri.return_value.content = fake_request_response("user")
        user = self.helper.get_sc_user_by_id(self.user_id)
        self.assertIsInstance(user, User)

    @patch('pytos.securechange.helpers.Secure_Change_Helper.get_sc_user_by_id')
    def test_06_reassign_task(self, mock_user_obj):
        mock_user_obj.return_value = User.from_xml_string(fake_request_response("user").decode())
        self.mock_get_uri.return_value.content = fake_request_response("ticket")
        ticket = self.helper.get_ticket_by_id(self.ticket_id)
        step_task_obj = ticket.get_current_task()
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.reassign_task(step_task_obj, self.user_id, 'Reassign message')
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/reassign/{}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, ticket.get_current_step().id, step_task_obj.id, self.user_id),
                auth=('username', 'password'),
                data='<reassign_task_comment>\n  <comment>Reassign message</comment>\n</reassign_task_comment>',
                headers={'Content-Type': 'application/xml'}
            )

    def test_07_change_requester(self):
        requester_id = 3
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.change_requester(self.ticket_id, requester_id, 'Modify requester')
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/change_requester/{}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, requester_id),
                auth=('username', 'password'),
                data='<comment>\n  <comment>Modify requester</comment>\n</comment>',
                headers={'Content-Type': 'application/xml'}
            )

    def test_08_cancel_ticket_with_requester(self):
        requester_id = 3
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            self.helper.cancel_ticket(self.ticket_id, requester_id)
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/cancel?requester_id={}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, requester_id),
                auth=('username', 'password'),
                data=None,
                headers={}
            )

    def test_09_put_task(self):
        self.mock_get_uri.return_value.content = fake_request_response("ticket")
        ticket = self.helper.get_ticket_by_id(self.ticket_id)
        last_task = ticket.get_last_task()
        text_field = last_task.get_field_list_by_type(xml_tags.Attributes.FIELD_TYPE_TEXT)[0]
        text_field.text = "new text"
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            result = self.helper.put_task(last_task)
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, ticket.get_current_step().id, last_task.id),
                auth=('username', 'password'),
                data=last_task.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertTrue(result)

    def test_10_put_field(self):
        self.mock_get_uri.return_value.content = fake_request_response("ticket")
        ticket = self.helper.get_ticket_by_id(self.ticket_id)
        last_task = ticket.get_last_task()
        text_field = last_task.get_field_list_by_type(xml_tags.Attributes.FIELD_TYPE_TEXT)[0]
        text_field.text = "new text"
        with patch('pytos.common.rest_requests.requests.Request') as mock_put_uri:
            result = self.helper.put_field(text_field)
            url = "https://localhost/securechangeworkflow/api/securechange/tickets/{}/steps/{}/tasks/{}/fields/{}"
            mock_put_uri.assert_called_with(
                'PUT',
                url.format(self.ticket_id, ticket.get_current_step().id, last_task.id, text_field.id),
                auth=('username', 'password'),
                data=text_field.to_xml_string().encode(),
                headers={'Content-Type': 'application/xml'}
            )
        self.assertTrue(result)

    def test_11_get_user_by_username(self):
        self.mock_get_uri.return_value.content = fake_request_response("users")
        user = self.helper.get_user_by_username("user")
        self.assertIsInstance(user, User)

    def test_12_get_ticket_ids_by_status(self):
        self.mock_get_uri.return_value.content = fake_request_response("tickets")
        status = "In Progress&desc=True"
        tickets = self.helper.get_ticket_ids_by_status(status)
        self.assertIsInstance(tickets, TicketList)

    def test_13_get_user_by_email(self):
        self.mock_get_uri.return_value.content = fake_request_response("users")
        users = self.helper.get_user_by_email("user@kuku.com")
        self.assertIsInstance(users, User_List)

    @patch('pytos.securechange.helpers.Secure_Change_Helper.get_user_by_username')
    def test_14_get_all_members_of_group(self, mock_group_obj):
        mock_group_obj.return_value = Group.from_xml_string(fake_request_response("users").decode())
        members = self.helper.get_all_members_of_group('Approver')
        self.assertEqual(members, ['d'])
    #
    # def test_27_get_all_members_of_group_by_group_id(self):
    #
    #     group_id = 6
    #     user_names = ["a", "b", "c"]
    #
    #     # assert valid request
    #     members = self.helper.get_all_members_of_group_by_group_id(group_id)
    #     members_names = [member.name for member in members]
    #     for user in user_names:
    #         self.assertTrue(user in members_names)
    #
    #     # assert invalid request
    #     with self.assertRaises(ValueError):
    #         self.helper.get_all_members_of_group_by_group_id(3)
    #
    # def test_29_get_verifier_results(self):
    #
    #     # global variable
    #     ticket_id = access_request_ticket_id
    #
    #     ticket = self.helper.get_ticket_by_id(ticket_id)
    #     last_task = ticket.get_last_task()
    #     last_step = ticket.get_last_step()
    #     ar_field = last_task.get_field_list_by_type(xml_tags.Attributes.FIELD_TYPE_MULTI_ACCESS_REQUEST)[0]
    #     # create a list of access request id's for calling the get_verifier_results API
    #     ar_ids = [ar.id for ar in ar_field.access_requests]
    #
    #     # assert the values of each result - These are valid requests
    #     for verifier, ar_id in zip(ar_field.get_all_verifier_results(), ar_ids):
    #         # assert the first 2 access request that we know they have verifier results
    #         if ar_ids.index(ar_id) in [0, 1]:
    #             verifier_result = self.helper.get_verifier_results(ticket_id, last_step.id, last_task.id, ar_id)
    #             self.assertIsInstance(verifier_result, AccessRequestVerifierResult)
    #             if ar_ids.index(ar_id) == 0:
    #                 # assert that the first AR is not implemented as excpected
    #                 self.assertTrue(verifier.is_not_implemented())
    #             else:
    #                 # assert that the first AR is implemented as excpected
    #                 self.assertTrue(verifier.is_implemented())
    #         # assert that the third AR is not available as excpected
    #         elif ar_ids.index(ar_id) == 2:
    #             try:
    #                 self.helper.get_verifier_results(ticket_id, last_step.id, last_task.id, ar_id)
    #             except ValueError as value_error:
    #                 self.assertIsInstance(value_error, ValueError)
    #                 self.assertTrue(verifier.is_not_available())
    #
    # def test_31_get_ticket_ids_with_expiration_date(self):
    #
    #     ticket_found = False
    #     tickets = self.helper.get_ticket_ids_with_expiration_date()
    #     for ticket in tickets:
    #         if access_request_ticket_id == ticket:
    #             ticket_found = True
    #
    #     self.assertIsInstance(tickets, types.GeneratorType)
    #     self.assertTrue(ticket_found)


if __name__ == '__main__':
    unittest.main()
