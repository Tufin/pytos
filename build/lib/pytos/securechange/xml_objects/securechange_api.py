
import enum
import logging
import sys

from pytos.common.base_types import XML_Object_Base, XML_List, Flat_XML_Object_Base
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.definitions.xml_tags import Elements
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value, get_xml_node

logger = logging.getLogger(XML_LOGGER_NAME)

TEST_MODE_VALUE = "test"


def get_ticket_id():
    """
    Function that tries to parse first argument passed to script as ticket id
    :rtype: str
    :return: ticket id of the ticket that triggered the script or "test" if used in test mode
    """
    try:
        ticket_id = sys.argv[1]
        if not ticket_id:
            raise ValueError
        logger.debug("Got ticket ID '%s'", ticket_id)
        if ticket_id == TEST_MODE_VALUE:
            logger.info("Script is called in test mode")
        else:
            logger.debug("Script is called for ticket ID %s.", ticket_id)
    except (IndexError, ValueError):
        msg = "Failed to get ticket ID from SecureChange"
        logger.critical(msg)
        raise IOError(msg)
    return ticket_id


class Ticket_Info(XML_Object_Base):
    def __init__(self, xml_node):
        # The base node has no child nodes, we are in test mode.
        if len(xml_node.getchildren()) == 0:
            raise ValueError("The ticket can not be constructed as the script is in test mode.")
        try:
            self.id = get_xml_int_value(xml_node, Elements.ID)
            self.subject = get_xml_text_value(xml_node, Elements.SUBJECT)
            self.createDate = get_xml_text_value(xml_node, Elements.CREATE_DATE)
            self.updateDate = get_xml_text_value(xml_node, Elements.UPDATE_DATE)
            current_stage_node = get_xml_node(xml_node, Elements.CURRENT_STAGE, True)
            if current_stage_node:
                self.current_stage_id = get_xml_int_value(current_stage_node, Elements.ID)
                self.current_stage_name = get_xml_text_value(current_stage_node, Elements.NAME)
            else:
                self.current_stage_id, self.current_stage_name = None, None

            completion_data = get_xml_node(xml_node, Elements.COMPLETION_DATA, True)
            if completion_data:
                self.completion_step_id = get_xml_int_value(completion_data, 'stage/' + Elements.ID)
                self.completion_step_name = get_xml_text_value(completion_data, 'stage/' + Elements.NAME)
            else:
                self.completion_step_id, self.completion_step_name = None, None

            self.open_request_id = get_xml_int_value(
                get_xml_node(xml_node, Elements.OPEN_REQUEST_STAGE), Elements.ID)
            self.open_request_name = get_xml_text_value(
                get_xml_node(xml_node, Elements.OPEN_REQUEST_STAGE), Elements.NAME)
        except AttributeError as attr_error:
            message = "Could not parse ticket_info XML into Ticket_Info object, error was {0}.".format(attr_error)
            logger.error(message)
            raise AttributeError(message)
        super().__init__(Elements.TICKET_INFO)


class Scripted_Dynamic_Assignment_Mode(enum.Enum):
    SELF = "self"
    AUTO = "auto"
    MANUAL = "manual"

    @staticmethod
    def validate(value):
        if value in [e.value for e in list(Scripted_Dynamic_Assignment_Mode)]:
            return True
        return False


class Scripted_Dynamic_Assignment(XML_List):
    """
    This class generates and sets dynamic assignments tasks for Access Requests
    """

    def __init__(self, tasks=None):

        if tasks is None:
            tasks = []
        super().__init__(Elements.TASKS, tasks)

    def add_task(self, name, participant_names, access_request_ids, assignment_mode, assigner_username=None):
        """
        Add new task to be send to SecureChange in order to be added in scripted dynamic assignment
        :param name: Name of new task
        :type name: str
        :param participant_names: List of participant names.
        :type participant_names: list[str]
        :param access_request_ids: List of access requests IDs that will be handled in the task.
        :type access_request_ids: list[int]
        :param assignment_mode: The task assignment mode.
        :type assignment_mode: str|Scripted_Dynamic_Assignment_Mode
        :param assigner_username: The username who will be the assigner for this task.
        :type assigner_username: str
        """
        self.append(Scripted_Dynamic_Assignment_Task(name, participant_names,
                                                     access_request_ids, assignment_mode,
                                                     assigner_username))

    def add_task_by_ids(self, name, participant_ids, access_request_ids, assignment_mode, assigner_id=None):
        """Add new task to be send to SecureChange in order to be added in scripted dynamic assignment
        :param name: String name of new task
        :param participant_ids: List of participant ids - list[int].
        :param access_request_ids: List of access requests IDs that will be handled in the task.
        :type access_request_ids: list[int]
        :param assignment_mode: The task assignment mode.
        :type assignment_mode: str|Scripted_Dynamic_Assignment_Mode
        :param assigner_id: The id who will be the assigner for this task.
        :type assigner_id: str
        """
        self.append(Scripted_Dynamic_Assignment_Task(name=name, participant_names=[],
                                                     access_request_ids=access_request_ids,
                                                     assignment_mode=assignment_mode, assigner_username=None,
                                                     participant_ids=participant_ids, assigner_id=assigner_id))

    def send_assignments_xml(self):
        """
        This function prints out to stdout the xml with the tasks, which is parsed by SecureChange.
        """
        print(self.to_xml_string())


class Scripted_Dynamic_Assignment_Task(XML_Object_Base):
    def __init__(self, name, participant_names, access_request_ids, assignment_mode,
                 assigner_username=None, participant_ids=None, assigner_id=None):
        self.name = name
        self.participants = Scripted_Dynamic_Assignment_Participants_Node(participant_names, participant_ids)
        self.access_requests = Scripted_Dynamic_Assignment_Access_Requests_Node(access_request_ids)
        self.assignment = Scripted_Dynamic_Assignment_Assignment_Node(assignment_mode, assigner_username, assigner_id)
        super().__init__(Elements.TASK)


class Scripted_Dynamic_Assignment_Access_Requests_Node(XML_List):
    def __init__(self, access_request_ids):
        self.access_requests = []
        if access_request_ids:
            for ar_id in access_request_ids:
                self.access_requests.append(Flat_XML_Object_Base(Elements.ACCESS_REQUEST_ID, content=ar_id))
        super().__init__(Elements.ACCESS_REQUESTS, self.access_requests)


class Scripted_Dynamic_Assignment_Participants_Node(XML_List):
    def __init__(self, participant_names=None, participant_ids=None):
        self.participants = Scripted_Dynamic_Assignment_Participants_Node._get_participants(participant_names,
                                                                                            participant_ids)
        super().__init__(Elements.PARTICIPANTS, self.participants)

    @staticmethod
    def _get_participants(names=None, ids=None):
        """Get participants object list by ids or names"""
        if ids:
            return [Flat_XML_Object_Base(Elements.PARTICIPANT_ID, content=id_) for id_ in ids]
        elif names:
            return [Flat_XML_Object_Base(Elements.PARTICIPANT_USERNAME, content=name_) for name_ in names]
        else:
            msg = "Failed to get either participants names or ids"
            raise AttributeError(msg)


class Scripted_Dynamic_Assignment_Assignment_Node(XML_Object_Base):
    def __init__(self, assignment_mode, assigner_username=None, assigner_id=None):
        try:
            self.assignment_mode = Scripted_Dynamic_Assignment_Mode(assignment_mode).value
        except ValueError:
            raise ValueError("Wrong assignment_mode '{}'".format(assignment_mode))
        if assigner_id:
            self.assigner_id = assigner_id
        elif assigner_username:
            self.assigner_username = assigner_username
        super().__init__(Elements.ASSIGNMENT)


# <?xml version="1.0" encoding="UTF-8"?>
# <ticket_info>
#    <id>1</id>
#    <subject>1</subject>
#    <createDate>1</createDate>
#    <updateDate>1</updateDate>
#    <current_stage>
#       <id>1</id>
#       <name>Current Step Name</name>
#    </current_stage>
#    <open_request_stage>
#       <id>1</id>
#       <name>Open Request Step Name</name>
#    </open_request_stage>
#   <current_stage>
#   <id>5</id><name>dfgffg</name></current_stage>
#   <open_request_stage><id>5</id><name>fghfghgf</name></open_request_stage>
# </ticket_info>
