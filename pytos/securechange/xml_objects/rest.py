import datetime
import time
import enum
from collections import OrderedDict

# For backward compatibility import FileLock
from pytos.securechange.xml_objects.restapi.step.rule_decommission.rule_decommission import Step_Field_Rule_Decommission
from pytos.securechange.xml_objects.restapi.step.server_decommission.server_decommission import Step_Field_Server_Decommission
from pytos.common.functions.utils import FileLock
from pytos.secureapp.xml_objects.base_types import Base_Link_Target, URL_Link
from pytos.securechange import definitions
from pytos.securechange.xml_objects.base_types import Step_Field_Base
from pytos.securechange.xml_objects.restapi.step.access_request.accessrequest import *
from pytos.common.base_types import XML_List, XML_Object_Base, Flat_XML_Object_Base, Comparable
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.functions import str_to_bool, get_xml_node, get_xml_text_value, get_xml_int_value
from pytos.common.functions import convert_timedelta_to_seconds
from pytos.common.definitions.xml_tags import TYPE_ANY, TYPE_ATTRIB, TYPE_DNS, TYPE_IP, TYPE_OBJECT, TYPE_NETWORK, \
    TYPE_HOST, SERVICE_OBJECT_TYPE_PREDEFINED, SERVICE_OBJECT_TYPE_PROTOCOL, Elements, Attributes

logger = logging.getLogger(XML_LOGGER_NAME)

# For backward compatibility use FileLock as Ticket_Lock too
Ticket_Lock = FileLock


class TicketList(XML_List):
    """
    :type tickets: list[Ticket]
    """

    def __init__(self, tickets):
        super().__init__(Elements.TICKETS, tickets)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        tickets = []
        for ticket_node in xml_node.findall(Elements.TICKET):
            tickets.append(Ticket.from_xml_node(ticket_node))
        return cls(tickets)


class TicketStatus(enum.Enum):
    # TODO: Move this enum to be used for all usage of ticket statuses
    Closed = "Ticket Closed"
    Cancelled = "Ticket Cancelled"
    Rejected = "Ticket Rejected"
    Resolved = "Ticket Resolved"
    InProgress = "In Progress"


class Ticket(XML_Object_Base):
    """
    This class represents a SecureChange ticket object.
    """

    EXPIRATION_DATE_FORMAT_STRING = "%Y-%m-%d"
    CLOSED_STATUS = "Ticket Closed"
    CANCELLED_STATUS = "Ticket Cancelled"
    REJECTED_STATUS = "Ticket Rejected"
    RESOLVED_STATUS = "Ticket Resolved"
    IN_PROGRESS_STATUS = "In Progress"

    def __init__(self, workflow, current_step, subject, ticket_id, priority, status, domain_name, sla_status,
                 sla_outcome, expiration_field_name, expiration_date, steps, comments, requester, application_details,
                 requester_id=None):
        self.steps = XML_List(Elements.STEPS, sorted(steps, key=lambda step: step.id))
        self.workflow = workflow
        self.current_step = current_step
        self.subject = subject
        self.id = ticket_id
        self.priority = priority
        self.status = status
        self.domain_name = domain_name
        self.sla_status = sla_status
        self.sla_outcome = sla_outcome
        self.expiration_field_name = expiration_field_name
        self.expiration_date = expiration_date
        self.comments = comments
        self.requester = requester
        self.requester_id = requester_id
        if application_details is not None:
            self.application_details = application_details
        super().__init__(Elements.TICKET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """

        steps = XML_List.from_xml_node_by_tags(xml_node, Elements.STEPS, Elements.STEP, Ticket_Step)
        workflow_node = get_xml_node(xml_node, Elements.WORKFLOW)
        workflow = Workflow.from_xml_node(workflow_node)
        subject = get_xml_text_value(xml_node, Elements.SUBJECT)
        requester = get_xml_text_value(xml_node, Elements.REQUESTER)
        requester_id = get_xml_int_value(xml_node, Elements.REQUESTER_ID)
        ticket_id = get_xml_int_value(xml_node, Elements.ID)
        priority = get_xml_text_value(xml_node, Elements.PRIORITY)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        domain_name = get_xml_text_value(xml_node, Elements.DOMAIN_NAME)
        sla_status = get_xml_text_value(xml_node, Elements.SLA_STATUS)
        sla_outcome = get_xml_text_value(xml_node, Elements.SLA_OUTCOME)
        expiration_field_name = get_xml_text_value(xml_node, Elements.EXPIRATION_FIELD_NAME)
        expiration_date = get_xml_text_value(xml_node, Elements.EXPIRATION_DATE)

        current_step_node = get_xml_node(xml_node, Elements.CURRENT_STEP, True)
        if current_step_node:
            current_step = Current_Step.from_xml_node(current_step_node)
        else:
            current_step = None

        application_details_node = get_xml_node(xml_node, Elements.APPLICATION_DETAILS, True)
        if application_details_node:
            application_details = Application_Details.from_xml_node(application_details_node)
        else:
            application_details = None

        comments = XML_List.from_xml_node_by_tags(xml_node, Elements.COMMENTS, Elements.COMMENT, Ticket_Comment, True)
        return cls(workflow, current_step, subject, ticket_id, priority, status, domain_name, sla_status, sla_outcome,
                   expiration_field_name, expiration_date, steps, comments, requester, application_details,
                   requester_id)

    def get_step_by_name(self, step_name, case_sensitive=True):
        """
        Get the ticket step whose name matches the specified name.
        :param step_name: The name of the ticket step that is to be returned.
        :type step_name: str
        :return: The ticket step whose name matches the specified name.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step
        :raise ValueError: If a ticket step with the specified name can not be found.
        """
        logger.debug("Steps are '%s', looking for step '%s'.", [step.name for step in self.steps], step_name)
        for step in self.steps:
            if case_sensitive:
                if step.name == step_name:
                    return step
            else:
                if step.name.lower() == step_name.lower():
                    return step
        raise ValueError("A ticket step with the name '%s' could not be found.", step_name)

    def get_current_step(self):
        """
        Return the current ticket step.
        :return: The current ticket step.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step

        """
        try:
            return self.get_step_by_id(self.current_step.id)
        except (AttributeError, ValueError):
            message = "The current step for this ticket is not set."
            logger.debug(message)
            raise KeyError(message)

    def get_current_task(self):
        """
        Return the last ticket step task.
        :return: The last ticket step task.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task

        """
        return self.get_current_step().get_last_task()

    def get_last_task(self):
        return self.get_current_task()

    def get_last_step(self):
        """
        Return the last ticket step.
        :return: The last ticket step.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step

        """
        return self.get_step_by_index(-1)

    def get_previous_step(self):
        """
        Return the previous ticket step.
        :return: The previous ticket step.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step

        """
        return self.get_step_by_index(-2)

    def get_first_step(self):
        """
        Return the first ticket step.
        :return: The first ticket step.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step

        """
        return self.get_step_by_index(0)

    def get_first_task(self):
        """
        Return the first ticket task.
        :return: The first ticket task.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task

        """
        return self.get_first_step().get_last_task()

    def get_step_by_id(self, step_id):
        """
        Get the ticket step whose ID matches the specified ID.
        :param step_id: The ID of the ticket step that is to be returned.
        :type step_id: int
        :return: The ticket step whose ID matches the specified ID.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step
        :raise ValueError: If a ticket step with the specified ID can not be found.
        """
        logger.debug("Ticket steps IDs are '%s', getting ticket step with ID '%s'", [step.id for step in self.steps],
                     step_id)
        for step in self.steps:
            if step.id == step_id:
                return step
        raise ValueError("A ticket step with the ID '{}' could not be found.".format(step_id))

    def get_step_by_index(self, step_index):
        """
        Get the ticket step whose index matches the specified index.
        :param step_index: The index of the ticket step that is to be returned.
        :type step_index: int
        :return: The ticket step whose index matches the specified index.
        :rtype: Secure_Change.XML_Objects.REST.Ticket_Step
        :raise ValueError: If a ticket step with the specified index can not be found.
        """
        logger.debug("Ticket steps IDs are '%s', getting ticket step with index '%s'", self.steps, step_index)
        # Check that index is not larger than the amount of steps that exist.
        step_ids = [step.id for step in self.steps]
        logger.debug("Sorted step ID list is %s", step_ids)
        return self.get_step_by_id(step_ids[step_index])

    def get_last_worked_on_step(self):
        """
            Get step that was last worked on
            :return: Step
            :rtype: int
            :raise ValueError: If no step is found
            """
        logger.debug("Searching for the step last worked on.")
        last_step = None
        for step in self.steps:
            if any((task for task in step.tasks if task.status == "DONE")) and (
                        not last_step or step.id > last_step.id):
                last_step = step
        if not last_step:
            raise ValueError("No step is found that was last worked on for ticket {}".format(self.id))
        return last_step

    def get_rejected_step(self):
        logger.info("Getting rejected step")
        if self.status != self.REJECTED_STATUS:
            return None
        for step in self.steps:
            for task in step.tasks:
                try:
                    approve_reject_field = task.get_field_list_by_type(Attributes.FIELD_TYPE_APPROVE_REJECT)[0]
                except IndexError:
                    continue
                if approve_reject_field.approved and not str_to_bool(approve_reject_field.approved):
                    return step

        logger.debug("No step was found that was rejected for ticket {}".format(self.id))
        return None

    def get_last_worked_on_step_id(self):
        """
        Get step ID that was last worked on
        :return: Step ID
        :rtype: int
        :raise ValueError: If no step ID is found
        """
        logger.debug("Searching for ID of the step last worked on.")
        last_id = None
        for step in self.steps:
            if any((task for task in step.tasks if task.status == "DONE")) and (not last_id or step.id > last_id):
                last_id = step.id
        if not last_id:
            raise ValueError("No ID is found for last worked on step for ticket {}".format(self.id))
        return last_id

    def is_closed(self):
        if self.status == Ticket.CLOSED_STATUS:
            return True
        else:
            return False

    def is_cancelled(self):
        if self.status == Ticket.CANCELLED_STATUS:
            return True
        else:
            return False

    def is_rejected(self):
        if self.status == Ticket.REJECTED_STATUS:
            return True
        else:
            return False

    def is_resolved(self):
        if self.status == Ticket.RESOLVED_STATUS:
            return True
        else:
            return False

    def is_in_progress(self):
        if self.status == Ticket.IN_PROGRESS_STATUS:
            return True
        else:
            return False

    def get_expiry_days_left(self):
        if self.expiration_date is not None:
            expiration_date = datetime.datetime.strptime(self.expiration_date, Ticket.EXPIRATION_DATE_FORMAT_STRING)
            return (expiration_date.date() - datetime.date.today()).days
        raise ValueError("Expiration date is not set!")

    def step_index(self, step):
        """
        Gets the index of the provided step in the ticket.
        :param step: The ticket step.
        :return: The index of the step in the ticket.
        :rtype int
        """
        return self.steps.index(step)

    def templatize(self):
        """
        Prepare a ticket for use as a template.
        :return:
        """
        self.sanitize_ids()
        del self.steps[1:]
        self.current_step = None

    @staticmethod
    def has_no_pending_tasks(ticket):
        return not any(task.is_pending() for task in ticket.get_current_step().tasks)


class Ticket_Comment(XML_Object_Base):
    def __init__(self, content, created, task_name, comment_type, user):
        self.content = content
        self.created = created
        self.task_name = task_name
        self.type = comment_type
        self.user = user
        super().__init__(Elements.COMMENT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        content = get_xml_text_value(xml_node, Elements.CONTENT)
        created = get_xml_text_value(xml_node, Elements.CREATED)
        task_name = get_xml_text_value(xml_node, Elements.TASK_NAME)
        comment_type = get_xml_text_value(xml_node, Elements.TYPE)
        user = get_xml_text_value(xml_node, Elements.USER)
        return cls(content, created, task_name, comment_type, user)


class Current_Step(XML_Object_Base):
    """
    This class represents the current step node in a SecureChange ticket object
    """

    def __init__(self, num_id, name):
        self.id = num_id
        self.name = name
        super().__init__(Elements.CURRENT_STEP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        step_id = get_xml_int_value(xml_node, Elements.ID)
        step_name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(step_id, step_name)


class Ticket_Step(XML_Object_Base):
    """
    This class represents a step node in a SecureChange ticket object
    """

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        step_id = get_xml_int_value(xml_node, Elements.ID)
        step_name = get_xml_text_value(xml_node, Elements.NAME)
        skipped = get_xml_text_value(xml_node, Elements.SKIPPED)
        redone = get_xml_text_value(xml_node, Elements.REDONE)
        tasks = XML_List.from_xml_node_by_tags(xml_node, Elements.TASKS, Elements.TASK, Step_Task)
        return cls(step_id, step_name, redone, skipped, tasks)

    def __init__(self, num_id, name, redone, skipped, tasks):
        """
        Initialize the object from parameters.
        :param tasks: The task object for this step.
        :type tasks: list[Step_Task]
        """
        self.id = num_id
        self.name = name
        self.redone = redone
        self.skipped = skipped
        self.tasks = tasks
        super().__init__(Elements.STEP)

    def get_task_by_id(self, task_id):
        """
        Get the step task whose ID matches the specified ID.
        :param task_id: The ID of the step task that is to be returned.
        :type task_id: int
        :return: The step task whose ID matches the specified ID.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task
        :raise ValueError: If a step task with the specified ID can not be found.
        """
        for task in self.tasks:
            if task.id == task_id:
                logger.debug("Returning task with ID '%s': '%s'", task_id, task.to_xml_string())
                return task
        raise ValueError("A step task with the ID {} can not be found.".format(task_id))

    def get_task_by_index(self, task_index):
        """
        Get the step task whose index matches the specified index.
        :param task_index: The index of the step task that is to be returned.
        :type task_index: int
        :return: The step task whose index matches the specified index.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task
        :raise ValueError: If a step task with the specified index can not be found.
        """
        num_of_existing_tasks = len(self.tasks)
        if num_of_existing_tasks < task_index + 1:
            raise ValueError("A task with an index of '{}' can not be found, highest index is '{}'.".format(task_index,
                                                                                                            num_of_existing_tasks - 1))
        task_ids = []
        for task in self.tasks:
            task_ids.append(task.id)
        task_ids.sort()
        logger.debug("Returning task with index of '%s'", task_index)
        return self.get_task_by_id(task_ids[task_index])

    def get_task_by_name(self, task_name):
        """
        Get the step task whose name matches the specified name.
        :param task_name: The name of the task that is to be returned.
        :type task_name: str
        :return: The step task whose ID matches the specified name.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task
        :raise ValueError: If a step task with the specified name can not be found.
        """
        for task in self.tasks:
            if task.name == task_name:
                logger.debug("Returning task with name '%s': '%s'", task_name, task.to_xml_string())
                return task
        raise ValueError("A step task with the name {} can not be found.".format(task_name))

    def get_last_task(self):
        """
        Get the last step task sorted by index.
        :return: The step task whose index matches the specified index.
        :rtype: Secure_Change.XML_Objects.REST.Step_Task
        """
        return self.get_task_by_index(-1)

    def is_redone(self):
        """
        :return: Has the current step been redone.
        :rtype: bool
        """
        return str_to_bool(self.redone)

    def is_skipped(self):
        """
        :return: Has the current step been skipped.

        :rtype: bool
        """
        return str_to_bool(self.skipped)


# To keep backward compatibility with previous projects

class Step_Field_Checkbox(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "value"

    def __init__(self, num_id, name, value, read_only=None):
        self.value = value
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_CHECKBOX)

    def is_checked(self):
        if self.value == "true":
            return True
        else:
            return False

    def set_checked(self):
        self.value = "true"

    def set_unchecked(self):
        self.value = "false"

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_value = get_xml_text_value(xml_node, Elements.VALUE)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_value, field_read_only)


class Step_Field_Manager(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "text"

    def __init__(self, num_id, name, text, read_only=None):
        self.text = text
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MANAGER)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_text_area = get_xml_text_value(xml_node, Elements.TEXT)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_text_area, field_read_only)


class Step_Field_Text_Area(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "text"

    def __init__(self, num_id, name, text, read_only=None):
        self.text = text
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_TEXT_AREA)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_text_area = get_xml_text_value(xml_node, Elements.TEXT)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_text_area, field_read_only)


class Step_Field_Text(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "text"

    def __init__(self, num_id, name, text, read_only=None):
        self.text = text
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_TEXT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_text_area = get_xml_text_value(xml_node, Elements.TEXT)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_text_area, field_read_only)


class Step_Field_Multi_Text(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "text_fields"

    def __init__(self, num_id, name, text_fields, read_only=None):
        self.text_fields = text_fields
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_TEXT)

    @classmethod
    def from_xml_node(cls, xml_node):
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        text_fields = []
        for text_field_node in xml_node.iter(tag=Elements.TEXT_FIELD):
            text_field_id = get_xml_int_value(text_field_node, Elements.ID)
            text_field_text = get_xml_text_value(text_field_node, Elements.TEXT)
            text_fields.append(Text_Field(text_field_id, text_field_text))
        return cls(num_id, name, text_fields, read_only)

    def set_field_value(self, values):
        if isinstance(values, list):
            values = [Text_Field(None, v) if not isinstance(v, Text_Field) else v for v in values]
        elif not isinstance(values, Text_Field):
            values = Text_Field(None, values)
        super().set_field_value(values)


class Step_Field_Multi_Text_Area(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "text_fields"

    def __init__(self, num_id, name, text_fields, read_only=None):
        self.text_fields = text_fields
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_TEXT_AREA)

    @classmethod
    def from_xml_node(cls, xml_node):
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        text_areas = []
        for text_field_node in xml_node.iter(tag=Elements.TEXT_AREA):
            text_area_text = get_xml_text_value(text_field_node, Elements.TEXT)
            text_areas.append(Text_Area(text_area_text))
        return cls(num_id, name, text_areas, read_only)

    def set_field_value(self, values):
        if isinstance(values, list):
            values = [Text_Area(v) if not isinstance(v, Text_Area) else v for v in values]
        elif not isinstance(values, Text_Area):
            values = Text_Area(values)
        super().set_field_value(values)


class Text_Field(XML_Object_Base):
    def __init__(self, num_id, text):
        self.id = num_id
        self.text = text
        super().__init__(Elements.TEXT_FIELD)

    def __str__(self):
        if self.text:
            return self.text
        else:
            return ""

    @classmethod
    def from_xml_node(cls, xml_node):
        num_id = get_xml_int_value(xml_node, Elements.ID)
        text = get_xml_text_value(xml_node, Elements.TEXT)
        return cls(num_id, text)


class Text_Area(XML_Object_Base):
    def __init__(self, text):
        self.text = text
        super().__init__(Elements.TEXT_AREA)

    def __str__(self):
        if self.text:
            return self.text
        else:
            return ""

    @classmethod
    def from_xml_node(cls, xml_node):
        text = get_xml_text_value(xml_node, Elements.TEXT)
        return cls(text)


class Step_Field_Approve_Reject(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = ["approved", "reason"]

    def __init__(self, num_id, name, approved, reason, read_only=None):
        self.approved = approved
        self.reason = reason
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_APPROVE_REJECT)

    def approve(self, reason):
        logger.info("Setting approve/reject field to approved.")
        self.approved = "true"
        self.reason = reason

    def reject(self, reason):
        logger.info("Setting approve/reject field to rejected.")
        self.approved = "false"
        self.reason = reason

    def is_approved(self):
        if self.approved == "true":
            return True
        elif self.approved == "false":
            return False
        else:
            return None

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_approved = get_xml_text_value(xml_node, Elements.APPROVED)
        field_reason = get_xml_text_value(xml_node, Elements.REASON)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_approved, field_reason, field_read_only)


class Step_Field_Date(Step_Field_Base):
    DATE_FORMAT_STRING = "%Y-%m-%d"
    FIELD_CONTENT_ATTRIBUTES = "value"

    def __init__(self, num_id, name, date_value, read_only=None):
        self.value = date_value
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_DATE)

    def get_xml_datetime(self):
        return self.value + "T00:00:00"

    def get_remedy_datetime(self):
        REMEDY_DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%SZ"
        return time.mktime(datetime.datetime.strptime(self.value, REMEDY_DATE_FORMAT_STRING))

    def get_epoch_datetime(self):
        return time.mktime(datetime.datetime.strptime(self.value, Step_Field_Date.DATE_FORMAT_STRING).timetuple())

    def as_datetime_obj(self):
        return datetime.datetime.strptime(self.value, Step_Field_Date.DATE_FORMAT_STRING)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_date = get_xml_text_value(xml_node, Elements.VALUE)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_date, field_read_only)


class Step_Field_Time(Step_Field_Base):
    TIME_FORMAT_STRING = "%H:%M"
    FIELD_CONTENT_ATTRIBUTES = "value"

    def __init__(self, num_id, name, time_value, read_only=None):
        self.value = time_value
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_TIME)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_time = get_xml_text_value(xml_node, Elements.VALUE)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_time, field_read_only)


class Step_Field_Drop_Down_List(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "selection"

    def __init__(self, num_id, name, options, selection, read_only=None):
        self.options = XML_List(Elements.OPTIONS, options)
        self.selection = selection
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_DROP_DOWN_LIST)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        options = XML_List.from_xml_node_by_tags(xml_node, Elements.OPTIONS, Elements.OPTION, Option_Node)
        selection = get_xml_text_value(xml_node, Elements.SELECTION)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(num_id, name, options, selection, read_only)


class Step_Field_Multi_Target(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "targets"

    def __init__(self, num_id, name, targets, read_only=None):
        self.targets = targets
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_TARGET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        targets = []
        for target_node in xml_node.iter(tag=Elements.TARGET):
            target = Multi_Target_Object.from_xml_node(target_node)
            targets.append(target)

        return cls(num_id, name, targets, read_only)


class Step_Field_Multiple_Selection(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "selected_options"

    def __init__(self, num_id, name, options, selected_options, read_only=None):
        self.options = XML_List(Elements.OPTIONS, options)
        self.selected_options = XML_List(Elements.SELECTED_OPTIONS, selected_options)
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTIPLE_SELECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        options = XML_List.from_xml_node_by_tags(xml_node, Elements.OPTIONS, Elements.OPTION, Option_Node)
        selected_options = XML_List.from_xml_node_by_tags(xml_node, Elements.SELECTED_OPTIONS, Elements.SELECTED_OPTION,
                                                          Selected_Option)
        return cls(num_id, name, options, selected_options, read_only)


class Selected_Option(XML_Object_Base):
    def __init__(self, value):
        self.value = value
        super().__init__(Elements.SELECTED_OPTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        value = get_xml_text_value(xml_node, Elements.VALUE)
        return cls(value)

    def __str__(self):
        return self.value


class Option_Node(XML_Object_Base):
    def __init__(self, value):
        self.value = value
        super().__init__(Elements.OPTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        value = get_xml_text_value(xml_node, Elements.VALUE)
        return cls(value)


class Step_Field_Multi_Network_Object(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "network_objects"

    def __init__(self, num_id, name, network_objects, read_only=None):
        self.network_objects = network_objects
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)

        network_objects = []
        for network_object_node in xml_node.iter(tag=Elements.NETWORK_OBJECT):
            network_object_type = network_object_node.attrib[TYPE_ATTRIB]
            if network_object_type == TYPE_DNS:
                network_object = Network_Object_DNS_Host.from_xml_node(network_object_node)
            elif network_object_type == TYPE_IP:
                network_object = Network_Object_IP_Address.from_xml_node(network_object_node)
            elif network_object_type == TYPE_ANY:
                network_object = Network_Object_Any.from_xml_node(network_object_node)
            elif network_object_type == TYPE_OBJECT:
                network_object = Network_Object_Object.from_xml_node(network_object_node)
            else:
                raise ValueError("Unknown network object type {}.".format(network_object_type))
            network_objects.append(network_object)

        return cls(num_id, name, network_objects, read_only)


class Step_Field_Multi_Group_Change(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "group_changes"

    def __init__(self, num_id, name, implementation_status, group_changes=None, read_only=None):
        self.implementation_status = implementation_status
        self.group_changes = group_changes
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_GROUP_CHANGE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        implementation_status = get_xml_text_value(xml_node, Elements.IMPLEMENTATION_STATUS)
        group_changes = []
        for group_change_node in xml_node.findall(Elements.GROUP_CHANGE):
            group_change = Group_Change_Node.from_xml_node(group_change_node)
            group_changes.append(group_change)
        return cls(num_id, name, implementation_status, group_changes, read_only)

    def to_pretty_str(self):
        output = "Group Change field '{}'\n:".format(self.name)
        for group_change in self.group_changes:
            output += "\n{}\n".format(group_change.to_pretty_str())
        return output


class Group_Change_Node(XML_Object_Base):
    def __init__(self, name, management_name, members, change_implementation_status=None, management_id=None,
                 change_action=None):
        self.name = name
        self.management_name = management_name
        self.management_id = management_id
        self.members = members
        self.change_action = change_action
        self.change_implementation_status = change_implementation_status
        super().__init__(Elements.GROUP_CHANGE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_text_value(xml_node, Elements.MANAGEMENT_ID)
        attr_to_class_dict = {TYPE_OBJECT: Group_Change_Member_Object, TYPE_NETWORK: Group_Change_Member_Object,
                              TYPE_HOST: Group_Change_Member_Object}
        members = XML_List.from_xml_node_by_type_dict(xml_node, Elements.MEMBERS, Elements.MEMBER, attr_to_class_dict,
                                                      optional=True)
        change_implementation_status = get_xml_text_value(xml_node, Elements.CHANGE_IMPLEMENTATION_STATUS)
        change_action = get_xml_text_value(xml_node, Elements.CHANGE_ACTION)
        return cls(name, management_name, members, change_implementation_status=change_implementation_status,
                   management_id=management_id, change_action=change_action)

    def to_pretty_str(self):
        pretty_string = "Modify Group Request '{}':\n".format(self.name)
        pretty_string += "\tManagement Name: {}\n".format(self.management_name)
        pretty_string += "\tImplementation Status: {}\n".format(self.change_implementation_status)
        pretty_string += "\tMembers:\n"
        for member in self.members:
            pretty_string += member.to_pretty_str()
            pretty_string += "\n\t\tMember Status: {}\n".format(member.status)
        return pretty_string


class Multi_Target_Object(XML_Object_Base):
    def __init__(self, num_id, object_name, object_type, object_details, management_name, management_id, object_UID):

        self.id = num_id
        self.object_name = object_name
        self.object_type = object_type
        self.object_details = object_details
        self.object_UID = object_UID
        self.management_name = management_name
        self.management_id = management_id
        super().__init__(Elements.TARGET)

    def __str__(self):
        if all([self.object_name, self.object_details]):
            return "{}/{}".format(self.object_name, self.object_details)
        else:
            return ""

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        object_name = get_xml_text_value(xml_node, Elements.OBJECT_NAME)
        object_type = get_xml_text_value(xml_node, Elements.OBJECT_TYPE)
        object_details = get_xml_text_value(xml_node, Elements.OBJECT_DETAILS)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        object_UID = get_xml_text_value(xml_node, Elements.OBJECT_UID)
        return cls(num_id, object_name, object_type, object_details, management_name, management_id, object_UID)


class Group_Change_Member_Object(XML_Object_Base):
    def __init__(self, name, num_id, object_type, object_details, management_name, management_id, status, comment,
                 attr_type, uid=None, object_updated_status=None):
        self.name = name
        self.id = num_id
        self.object_UID = uid
        self.object_type = object_type
        self.object_details = object_details
        self.management_name = management_name
        self.management_id = management_id
        self.status = status
        self.comment = comment
        self.object_updated_status = object_updated_status
        super().__init__(Elements.MEMBER)
        self.set_attrib(TYPE_ATTRIB, attr_type)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        num_id = get_xml_int_value(xml_node, Elements.ID)
        object_type = get_xml_text_value(xml_node, Elements.OBJECT_TYPE)
        object_details = get_xml_text_value(xml_node, Elements.OBJECT_DETAILS)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        uid = get_xml_text_value(xml_node, Elements.OBJECT_UID)
        object_updated_status = get_xml_text_value(xml_node, Elements.OBJECT_UPDATED_STATUS)
        attr_type = xml_node.attrib[TYPE_ATTRIB]
        return cls(name, num_id, object_type, object_details, management_name, management_id, status, comment,
                   attr_type, uid, object_updated_status)

    def __str__(self):
        return self.to_pretty_str()

    def to_pretty_str(self):
        object_string = ""
        if self.management_name:
            object_string += "\n\t\tManagement Name: {}".format(self.management_name)
        if self.object_type:
            object_string += "\n\t\tObject Type: {}".format(self.object_type)
        if self.object_details:
            object_string += "\n\t\tObject Details: {}".format(self.object_details)
        return object_string


class Step_Field_Multi_Service(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "service_objects"

    def __init__(self, num_id, name, service_objects, read_only=None):
        self.service_objects = service_objects
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_SERVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        service_type_class_dict = {SERVICE_OBJECT_TYPE_PREDEFINED: Predefined_Service_Target,
                                   SERVICE_OBJECT_TYPE_PROTOCOL: Protocol_Service_Target,
                                   TYPE_OBJECT: Object_Access_Request_Target, TYPE_ANY: Any_Service_Target}

        service_objects = XML_List.from_xml_node_by_type_dict(xml_node, Elements.SERVICES, Elements.SERVICE,
                                                              service_type_class_dict, True)
        return cls(num_id, name, service_objects, read_only)

    def to_pretty_str(self):
        return ', '.join(service.to_pretty_str() for service in self.service_objects)


class Step_Field_Hyperlink(Step_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "url"

    def __init__(self, num_id, name, url, read_only=None):
        self.url = url
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_HYPERLINK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_url = get_xml_text_value(xml_node, Elements.URL)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        return cls(field_id, field_name, field_url, field_read_only)


class Step_Field_Multi_Hyperlink(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "hyperlinks"

    def __init__(self, num_id, name, hyperlinks, read_only=None):
        self.hyperlinks = hyperlinks
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_HYPERLINK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        hyperlinks = []
        for hyperlink_node in xml_node.iter(tag=Elements.HYPERLINK):
            hyperlinks.append(Hyperlink.from_xml_node(hyperlink_node))
        return cls(num_id, name, hyperlinks, read_only)


class Hyperlink(XML_Object_Base):
    def __init__(self, num_id, url):
        self.id = num_id
        self.url = url
        super().__init__(Elements.HYPERLINK)

    @classmethod
    def from_xml_node(cls, xml_node):
        num_id = get_xml_int_value(xml_node, Elements.ID)
        url = get_xml_text_value(xml_node, Elements.URL)
        return cls(num_id, url)


class Workflow(XML_Object_Base):
    def __init__(self, num_id, workflow_name):
        self.id = num_id
        self.name = workflow_name
        super().__init__(Elements.WORKFLOW)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        workflow_name = get_xml_text_value(xml_node, Elements.NAME)
        workflow_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(workflow_id, workflow_name)


class Network_Object_IP_Address(Target_Base):
    def __init__(self, num_id, ip_address, netmask):
        self.ip_address = ip_address
        self.netmask = netmask
        super().__init__(Elements.NETWORK_OBJECT, num_id, TYPE_IP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        ip_address = get_xml_text_value(xml_node, Elements.IP_ADDRESS)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        return cls(num_id, ip_address, netmask)

    def to_pretty_str(self):
        try:
            return "\n\t\tIP Address: {}\n\t\tSubnet Mask: {}".format(self.ip_address, self.netmask)
        except AttributeError:
            return "\n\t\tIP Address: {}\n\t\tSubnet Mask: 255.255.255.255".format(self.ip_address)

    def __str__(self):
        try:
            return "{}/{}".format(self.ip_address, self.netmask)
        except AttributeError:
            return "{}/32".format(self.ip_address)


class Network_Object_Object(Target_Base):
    def __init__(self, num_id, object_name, object_type, object_details, management_name, management_id, object_UID):
        self.id = num_id
        self.object_name = object_name
        self.object_type = object_type
        self.object_details = object_details
        self.object_UID = object_UID
        self.management_name = management_name
        self.management_id = management_id
        super().__init__(Elements.NETWORK_OBJECT, num_id, TYPE_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        object_name = get_xml_text_value(xml_node, Elements.OBJECT_NAME)
        object_type = get_xml_text_value(xml_node, Elements.OBJECT_TYPE)
        object_details = get_xml_text_value(xml_node, Elements.OBJECT_DETAILS)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        object_UID = get_xml_text_value(xml_node, Elements.OBJECT_UID)
        return cls(num_id, object_name, object_type, object_details, management_name, management_id, object_UID)

    def __str__(self):
        return "{} {}".format(self.management_name, self.object_details)

    def to_pretty_str(self):
        object_string = ""
        if self.management_name:
            object_string += "\n\t\tManagement Name: {}".format(self.management_name)
        if self.object_name:
            object_string += "\n\t\tObject Name: {}".format(self.object_name)
        if self.object_details:
            object_string += "\n\t\tObject Details: {}".format(self.object_details)
        if self.object_UID:
            object_string += "\n\t\tObject UID: {}".format(self.object_UID)
        if self.object_type:
            object_string += "\n\t\tObject Type: {}".format(self.object_type)
        return object_string


class Network_Object_Any(Target_Base):
    def __init__(self, num_id):
        super().__init__(Elements.NETWORK_OBJECT, num_id, TYPE_ANY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(num_id)

    def __str__(self):
        return "Any"

    @staticmethod
    def to_pretty_str():
        """
        :rtype : str
        """
        return "\n\t\tIP Address: Any"


class Network_Object_DNS_Host(Target_Base):
    def __init__(self, num_id, host_name, ip_address, dns_ip_addresses=None):
        self.host_name = host_name
        # on 15-4 the ip_address tag was removed.
        # on 16-1-HF2 it was implemented as list of IPs
        self.ip_address = ip_address
        self.dns_ip_addresses = dns_ip_addresses
        super().__init__(Elements.NETWORK_OBJECT, num_id, TYPE_DNS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        hostname = get_xml_text_value(xml_node, Elements.HOST_NAME)
        # on 15-4 the ip_address tag was removed.
        # on 16-1-HF2 it was implemented as list of IPs
        ip_address = get_xml_text_value(xml_node, Elements.IP_ADDRESS)
        dns_ip_addresses = XML_List.from_xml_node_by_tags(xml_node, Elements.DNS_IP_ADDRESSES, Elements.IP_ADDRESS,
                                                          IpAddress, optional=True)
        return cls(num_id, hostname, ip_address, dns_ip_addresses)

    def to_pretty_str(self):
        target_string = ""
        if self.ip_address:
            target_string += "\n\t\tIP Address: {}".format(self.ip_address)
        elif self.dns_ip_addresses:
            target_string += "\n\t\tIP Addresses: {}".format(
                '\n\t\t\t\t\t'.join([str(ip) for ip in self.dns_ip_addresses]))
        if self.host_name:
            target_string += "\n\t\tHostname: {}".format(self.host_name)
        return target_string

    def __str__(self):
        if self.ip_address:
            return "{}/{}".format(self.host_name, self.ip_address)
        return "{}/{}".format(self.host_name, [str(ip) for ip in self.dns_ip_addresses])


class Step_Task(XML_Object_Base):
    """
    This class represents a task node in a ticket step in a SecureChange ticket object
    """

    def __init__(self, num_id, assignee, status, fields, name=None, assignee_id=None):
        self.id = num_id
        self.assignee = assignee
        self.status = status
        self.fields = XML_List(Elements.FIELDS, fields)
        self.name = name
        self.assignee_id = assignee_id

        super().__init__(Elements.TASK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        assignee = get_xml_text_value(xml_node, Elements.ASSIGNEE)
        assignee_id = get_xml_int_value(xml_node, Elements.ASSIGNEE_ID)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        task_name = get_xml_text_value(xml_node, Elements.NAME)
        field_type_to_class_dict = {Attributes.FIELD_TYPE_APPROVE_REJECT: Step_Field_Approve_Reject,
                                    Attributes.FIELD_TYPE_CHECKBOX: Step_Field_Checkbox,
                                    Attributes.FIELD_TYPE_DATE: Step_Field_Date,
                                    Attributes.FIELD_TYPE_DROP_DOWN_LIST: Step_Field_Drop_Down_List,
                                    Attributes.FIELD_TYPE_HYPERLINK: Step_Field_Hyperlink,
                                    Attributes.FIELD_TYPE_MANAGER: Step_Field_Manager,
                                    Attributes.FIELD_TYPE_MULTI_ACCESS_REQUEST: Step_Field_Multi_Access_Request,
                                    Attributes.FIELD_TYPE_MULTI_GROUP_CHANGE: Step_Field_Multi_Group_Change,
                                    Attributes.FIELD_TYPE_MULTI_HYPERLINK: Step_Field_Multi_Hyperlink,
                                    Attributes.FIELD_TYPE_MULTI_NETWORK_OBJECT: Step_Field_Multi_Network_Object,
                                    Attributes.FIELD_TYPE_MULTI_SERVICE: Step_Field_Multi_Service,
                                    Attributes.FIELD_TYPE_MULTI_TARGET: Step_Field_Multi_Target,
                                    Attributes.FIELD_TYPE_MULTI_TEXT: Step_Field_Multi_Text,
                                    Attributes.FIELD_TYPE_MULTI_TEXT_AREA: Step_Field_Multi_Text_Area,
                                    Attributes.FIELD_TYPE_MULTIPLE_SELECTION: Step_Field_Multiple_Selection,
                                    Attributes.FIELD_TYPE_TEXT: Step_Field_Text,
                                    Attributes.FIELD_TYPE_TEXT_AREA: Step_Field_Text_Area,
                                    Attributes.FIELD_TYPE_TIME: Step_Field_Time,
                                    Attributes.FIELD_TYPE_RULE_DECOMMISSION: Step_Field_Rule_Decommission,
                                    Attributes.FIELD_TYPE_MULTI_SERVER_DECOMMISSION_REQUEST:
                                        Step_Field_Server_Decommission
                                    }
        fields = XML_List.from_xml_node_by_type_dict(xml_node, Elements.FIELDS, Elements.FIELD,
                                                     field_type_to_class_dict)
        return cls(num_id, assignee, status, fields, task_name, assignee_id)

    def get_field_by_id(self, field_id):
        """
        Get the task field whose ID matches the specified ID.
        :param field_id: The ID of the task field that is to be returned.
        :type field_id: int
        :return: The task field whose ID matches the specified ID.
        :rtype: Can be any of Secure_Change.XML_Objects.REST.Step_Field*
        :raise ValueError: If a task field with the specified ID can not be found.
        """
        for field in self.fields:
            if field.id == field_id:
                return field
        raise ValueError("A field with an ID of '{}' could not be found.".format(field_id))

    def get_field_by_index(self, field_index):
        """
        Get the task field whose index matches the specified index.
        :param field_index: The index of the task field that is to be returned.
        :type field_index: int
        :return: The task field whose index matches the specified index.
        :rtype: Can be any of Secure_Change.XML_Objects.REST.Step_Field*
        :raise ValueError: If a task field with the specified index can not be found.
        """
        num_of_existing_fields = len(self.fields)
        if num_of_existing_fields < field_index + 1:
            raise ValueError("A field with an index of '{}' can not be found, "
                             "highest index is '{}'.".format(field_index, num_of_existing_fields - 1))
        field_ids = []
        for field in self.fields:
            field_ids.append(field.id)
        field_ids.sort()
        return self.get_field_by_id(field_ids[field_index])

    def get_field_list_by_name(self, field_name, case_sensitive=True):
        """
        Get the task fields whose names matches the specified name.
        :param field_name: The name of the task field that is to be returned.
        :type field_name: string
        :return: The task fields whose types matches the specified type.
        :rtype: list[T <= Secure_Change.XML_Objects.REST.Step_Field_Base]
        """
        field_list = []
        logger.debug("Field names are '%s', looking for field '%s'.", [field.name for field in self.fields], field_name)
        for field in self.fields:
            if case_sensitive:
                if field.name == field_name:
                    field_list.append(field)
            else:
                if field.name.lower() == field_name.lower():
                    field_list.append(field)

        return field_list

    def get_field_list_by_name_and_type(self, field_name, field_type, case_sensitive=True):
        """
        Get the task fields whose names and types match the specified name and type.
        :param field_name: The name of the task field that is to be returned.
        :type field_name: string
        :param field_type: The type of the task field that is to be returned.
        :type field_type: string
        :return: The task fields that match the specified name and type.
        :rtype: list[Secure_Change.XML_Objects.REST.Step_Field_Base]
        """
        field_list = []
        for field in self.fields:
            if case_sensitive:
                if field.name == field_name and field.get_field_type() == field_type:
                    field_list.append(field)
            else:
                if field.name.lower() == field_name.lower() and field.get_field_type() == field_type:
                    field_list.append(field)

        return field_list

    def get_fields_by_name(self, field_name, case_sensitive=True):
        """
        Get the task fields whose names matches the specified name.
        :param field_name: The name of the task field that is to be returned.
        :type field_name: string
        :return: The task fields whose types matches the specified type.
        :rtype: A generator object of Secure_Change.XML_Objects.REST.Step_Field*
        """
        logger.debug("Field names are '%s', looking for field '%s'.", [field.name for field in self.fields], field_name)
        for field in self.fields:
            if case_sensitive:
                if field.name.strip() == field_name.strip():
                    yield field
            else:
                if field.name.lower().strip() == field_name.lower().strip():
                    yield field

    def get_field_list_by_type(self, field_type):
        """
        Get the task fields whose types matches the specified type.
        :param field_type: The type of the task field that is to be returned.
        :type field_type: string
        :return: The task fields whose types matches the specified type.
        :rtype: list[T <= Step_Field_Base]
        """
        field_list = []
        for field in self.fields:
            if field.get_field_type() == field_type:
                field_list.append(field)
        return field_list

    def get_fields_by_type(self, field_type):
        """
        Get the task fields whose types matches the specified type.
        :param field_type: The type of the task field that is to be returned.
        :type field_type: string
        :return: The task fields whose types matches the specified type.
        :rtype: list[T <= Step_Field_Base]
        """
        for field in self.fields:
            if field.get_field_type() == field_type:
                yield field

    def mark_as_done(self):
        """Mark the current ticket step as done."""
        self.status = "DONE"

    def is_assigned(self):
        """Check if the task is assigned"""
        if self.status == "ASSIGNED":
            return True
        else:
            return False

    def is_waiting_to_be_assigned(self):
        """Check if the task is waiting to be assigned"""
        if self.status == "WAITING_TO_BE_ASSIGNED":
            return True
        else:
            return False

    def is_pending(self):
        """Check if the task is pending."""
        if self.status == "PENDING":
            return True
        else:
            return False

    def is_done(self):
        return self.status == "DONE"

    def remove_all_fields(self):
        """
        Remove all the fields from the task.
        Usually used to handle a case where there are read only fields in the task and they cannot be updated.
        """
        self.fields = None

    def remove_read_only_fields(self):
        """
        Remove all read only field in a task.
        """
        self.fields = XML_List(Elements.FIELDS, [field for field in self.fields if
                                                 not field.read_only or not str_to_bool(field.read_only)])

    def remove_access_request_field(self):
        """
        Remove access request field for a task.
        Need to use it when trying to put task with risk analysis results or verifier results
        """
        self.fields = XML_List(Elements.FIELDS, [field for field in self.fields if
                                                 field.FIELD_CONTENT_ATTRIBUTES != Elements.ACCESS_REQUESTS])


class User_List(XML_List):
    """
    :type users: list[Group|User]
    """

    def __init__(self, users):
        super().__init__(Elements.USERS, users)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        users = []
        for user_node in xml_node.findall(Elements.USER):
            user_type = None
            try:
                user_type = user_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
            except (AttributeError, TypeError, KeyError) as error:
                logger.error(
                    "Failed to get the type of the User_List element. Assuming it's User. Error: {}".format(error))
            if user_type == "group":
                user = Group.from_xml_node(user_node)
            else:
                user = User.from_xml_node(user_node)
            users.append(user)
        return cls(users)


class User(XML_Object_Base):
    def __init__(self, user_id, user_name, user_email, out_of_office_from, out_of_office_until, send_email, notes,
                 ldapDn, first_name=None, last_name=None, display_name=None, groups=None, roles=None, domains=None,
                 auth_method=None, user_type_attrib=None, user_type=None, origin=None, managed_locally=None,
                 ldap_configuration=None, user_phone=None):
        self.id = user_id
        self.name = user_name
        self.first_name = first_name
        self.last_name = last_name
        self.display_name = display_name
        self.email = user_email
        self.phone = user_phone
        self.out_of_office_from = out_of_office_from
        self.out_of_office_until = out_of_office_until
        self.send_email = send_email
        self.notes = notes
        self.ldapDn = ldapDn
        self.member_of = groups
        self.roles = roles
        self.domains = domains
        self.authentication_method = auth_method
        self.type = user_type
        self.origin_type = origin
        self.managed_locally = managed_locally
        self.ldap_configuration = ldap_configuration
        # FIXME: name tag should be reused for that one
        self.user_name = user_name
        super().__init__(Elements.USER)
        if user_type_attrib:
            self.set_attrib(Attributes.XSI_NAMESPACE_TYPE, user_type_attrib)

    def get_name_fields(self):
        return self.name, self.display_name

    @classmethod
    def instantiate_ldap_user_object(cls, user_name, managed_locally=None, ldap_configuration=None):
        # TODO: Check if managed_locally should be set as enum instead of string
        """
        :param user_name: the name of the user to import from ldap
        :type user_name: str
        :param managed_locally: "true" or "false"
        :type managed_locally: str
        :param ldap_configuration: the list of the ldap config IDs to import from
        :type ldap_configuration: int|str|list|tuple|XML_List
        :return: user object ready to post to SC in order to import user
        :rtype: User
        """
        if isinstance(ldap_configuration, (int, str)):
            ldap_config_ids = [Flat_XML_Object_Base(Elements.ID, content=ldap_configuration)]
            ldap_configuration = XML_List(Elements.LDAP_CONFIGURATION, ldap_config_ids)
        elif isinstance(ldap_configuration, (list, tuple)):
            ldap_config_ids = [Flat_XML_Object_Base(Elements.ID, content=ldap_id) for ldap_id in ldap_configuration]
            ldap_configuration = XML_List(Elements.LDAP_CONFIGURATION, ldap_config_ids)
        return cls(None, user_name, None, None, None, None, None, None, origin="LDAP",
                   ldap_configuration=ldap_configuration, managed_locally=managed_locally)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        user_id = get_xml_int_value(xml_node, Elements.ID)
        user_name = get_xml_text_value(xml_node, Elements.NAME)
        first_name = get_xml_text_value(xml_node, Elements.FIRST_NAME)
        last_name = get_xml_text_value(xml_node, Elements.LAST_NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        user_email = get_xml_text_value(xml_node, Elements.EMAIL)
        out_of_office_from = get_xml_text_value(xml_node, Elements.OUT_OF_OFFICE_FROM)
        out_of_office_until = get_xml_text_value(xml_node, Elements.OUT_OF_OFFICE_UNTIL)
        send_email = get_xml_text_value(xml_node, Elements.SEND_EMAIL)
        user_phone = get_xml_text_value(xml_node, Elements.PHONE)
        notes = get_xml_text_value(xml_node, Elements.NOTES)
        ldapDn = get_xml_text_value(xml_node, Elements.LDAPDN)
        user_type = get_xml_text_value(xml_node, Elements.TYPE)
        groups = []
        groups_node = get_xml_node(xml_node, Elements.MEMBER_OF, True)
        if groups_node:
            for group_node in groups_node.iter(tag=Elements.USER):
                groups.append(Group.from_xml_node(group_node))
        roles = []
        roles_node = get_xml_node(xml_node, Elements.ROLES, True)
        if roles_node:
            roles = Roles.from_xml_node(roles_node)
        domains = []
        domains_node = get_xml_node(xml_node, Elements.DOMAINS, True)
        if domains_node:
            domains = Domains.from_xml_node(domains_node)

        auth_method = get_xml_text_value(xml_node, Elements.AUTHENTICATION_METHOD)
        try:
            user_type_attrib = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            user_type_attrib = None
        return cls(user_id, user_name, user_email, out_of_office_from, out_of_office_until, send_email, notes, ldapDn,
                   first_name, last_name, display_name, groups, roles, domains, auth_method, user_type_attrib,
                   user_type, user_phone)


class Group_Permission(XML_Object_Base):
    def __init__(self, permission_name, permission_value):
        self.name = permission_name
        self.value = permission_value
        super().__init__(Elements.GROUPPERMISSION)

    @classmethod
    def from_xml_node(cls, xml_node):
        permission_name = get_xml_text_value(xml_node, Elements.NAME)
        permission_value = get_xml_text_value(xml_node, Elements.VALUE)
        return cls(permission_name, permission_value)


class Group_Permissions(XML_List):
    """
    :type group_permissions: list[Group_Permission]
    """

    def __init__(self, group_permissions):
        super().__init__(Elements.GROUPPERMISSIONS, group_permissions)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        group_permissions = []
        for permission_node in xml_node.iter(tag=Elements.GROUPPERMISSION):
            group_permissions.append(Group_Permission.from_xml_node(permission_node))
        return cls(group_permissions)


class Member_User(XML_Object_Base):
    def __init__(self, user_id, user_name, link, user_type):
        self.id = user_id
        self.name = user_name
        self.link = link
        super().__init__(Elements.USER)
        self.set_attrib(Attributes.XSI_NAMESPACE_TYPE, user_type)

    @classmethod
    def from_xml_node(cls, xml_node):
        user_id = get_xml_int_value(xml_node, Elements.ID)
        user_name = get_xml_text_value(xml_node, Elements.NAME)
        link = get_xml_text_value(xml_node, Elements.LINK)
        user_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        return cls(user_id, user_name, link, user_type)


class Members(XML_List):
    def __init__(self, members_list, partial_list):
        self.partial_list = partial_list
        super().__init__(Elements.MEMBERS, members_list)

    @classmethod
    def from_xml_node(cls, xml_node):
        partial_list = get_xml_text_value(xml_node, Elements.PARTIAL_LIST)
        members_list = []
        for user_node in xml_node.iter(tag=Elements.USER):
            members_list.append(Member_User.from_xml_node(user_node))
        members_list.sort(key=lambda member: member.id)
        return cls(members_list, partial_list)


class Group(XML_Object_Base):
    def __init__(self, user_id, user_name, user_email, out_of_office_from, out_of_office_until, send_email, notes,
                 ldapDn, group_permission, members, user_type=None, roles=None):
        self.id = user_id
        self.name = user_name
        self.email = user_email
        self.out_of_office_from = out_of_office_from
        self.out_of_office_until = out_of_office_until
        self.send_email = send_email
        self.notes = notes
        self.ldapDn = ldapDn
        self.group_permission = group_permission
        self.members = members
        self.type = user_type
        self.roles = roles
        super().__init__(Elements.GROUP)

    def get_name_fields(self):
        return self.name,

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        user_id = get_xml_int_value(xml_node, Elements.ID)
        user_name = get_xml_text_value(xml_node, Elements.NAME)
        user_email = get_xml_text_value(xml_node, Elements.EMAIL)
        out_of_office_from = get_xml_text_value(xml_node, Elements.OUT_OF_OFFICE_FROM)
        out_of_office_until = get_xml_text_value(xml_node, Elements.OUT_OF_OFFICE_UNTIL)
        send_email = get_xml_text_value(xml_node, Elements.SEND_EMAIL)
        notes = get_xml_text_value(xml_node, Elements.NOTES)
        user_type = get_xml_text_value(xml_node, Elements.TYPE)
        ldapDn = get_xml_text_value(xml_node, Elements.LDAPDN)
        g_permission_node = get_xml_node(xml_node, Elements.GROUPPERMISSIONS, True)
        if g_permission_node:
            group_permission = Group_Permissions.from_xml_node(g_permission_node)
        else:
            group_permission = None

        members_node = get_xml_node(xml_node, Elements.MEMBERS, True)
        if members_node:
            members = Members.from_xml_node(members_node)
        else:
            members = []
        roles_node = get_xml_node(xml_node, Elements.ROLES, True)
        if roles_node:
            roles = Roles.from_xml_node(roles_node)
        else:
            roles = []
        return cls(user_id, user_name, user_email, out_of_office_from, out_of_office_until, send_email, notes, ldapDn,
                   group_permission, members, user_type, roles)


class Role(XML_Object_Base):
    def __init__(self, role_id, role_name):
        self.id = role_id
        self.name = role_name
        super().__init__(Elements.ROLE)

    @classmethod
    def from_xml_node(cls, xml_node):
        role_id = get_xml_int_value(xml_node, Elements.ID)
        role_name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(role_id, role_name)


class Roles(XML_List):
    """
    :type roles_list: list[Role]
    """

    def __init__(self, roles_list):
        self.roles = roles_list
        super().__init__(Elements.ROLES, roles_list)

    @classmethod
    def from_xml_node(cls, xml_node):
        roles_list = []
        for role_node in xml_node.iter(tag=Elements.ROLE):
            roles_list.append(Role.from_xml_node(role_node))
        return cls(roles_list)


class Domain(XML_Object_Base):
    def __init__(self, domain_id, domain_name):
        self.id = domain_id
        self.name = domain_name
        super().__init__(Elements.DOMAIN)

    @classmethod
    def from_xml_node(cls, xml_node):
        domain_id = get_xml_int_value(xml_node, Elements.ID)
        domain_name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(domain_id, domain_name)


class Domains(XML_List):
    """
    :type domains: list[Domain]
    """

    def __init__(self, domains):
        self.domains = domains
        super().__init__(Elements.DOMAINS, domains)

    @classmethod
    def from_xml_node(cls, xml_node):
        domains = []
        for domain_node in xml_node.iter(tag=Elements.DOMAIN):
            domains.append(Domain.from_xml_node(domain_node))
        return cls(domains)


class MultiGroupChangeImplementResult(XML_Object_Base):
    def __init__(self, task_id, task_name, group_changes, implementation_status):
        self.id = task_id
        self.name = task_name
        self.implementation_status = implementation_status
        self.group_changes = group_changes
        super().__init__(Elements.MULTI_ACCESS_REQUESTS)

    @classmethod
    def from_xml_node(cls, xml_node):
        task_id = get_xml_int_value(xml_node, Elements.ID)
        task_name = get_xml_text_value(xml_node, Elements.NAME)
        implementation_status = get_xml_text_value(xml_node, Elements.IMPLEMENTATION_STATUS)
        group_changes = []
        for group_change_node in xml_node.findall(Elements.GROUP_CHANGE):
            group_change = Group_Change_Node.from_xml_node(group_change_node)
            group_changes.append(group_change)
        return cls(task_id, task_name, group_changes, implementation_status)


class Ticket_History_Activities(XML_List):
    """
    This class represents a SecureChange ticket history object.
    """

    def __init__(self, ticket_id, ticket_activities):

        self.ticket_id = ticket_id
        self._step_durations = {}
        super().__init__(Elements.TICKET_HISTORY_ACTIVITIES, ticket_activities)
        self.sort()

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        ticket_id = get_xml_int_value(xml_node, Elements.TICKET_ID)
        history_activities = []
        for history_activity_node in xml_node.iter(tag=Elements.TICKET_HISTORY_ACTIVITY):
            history_activities.append(Ticket_History_Activity.from_xml_node(history_activity_node))
        return cls(ticket_id, history_activities)

    def sort(self):
        self._list_data = sorted(self._list_data, key=lambda x: x.as_time_obj_with_tz())

    def get_step_durations(self, time_unit_in_seconds=definitions.Time_Units.Seconds.value):
        step_times = OrderedDict()
        step_durations = OrderedDict()
        previous_step_name = None
        step_name = None
        step_index = None
        first_step_name = self[0].step_name
        for step_index, step in enumerate(self):
            if step.step_name == first_step_name:
                continue
            elif not step.step_name:
                logger.warn("Step name for entry in index %s in ticket history is empty.", step_index)
            if step.step_name != previous_step_name:
                step_times[step.step_name] = {"start": self[step_index].as_time_obj()}
                if previous_step_name:
                    step_times[previous_step_name]["end"] = self[step_index - 1].as_time_obj()
            previous_step_name = step.step_name
        try:
            step_times[step_name]["end"] = self[step_index].as_time_obj()
        except KeyError:
            pass
        for step in step_times:
            try:
                step_durations[step] = convert_timedelta_to_seconds(
                    step_times[step]["end"] - step_times[step]["start"]) / time_unit_in_seconds
            except KeyError:
                logger.error("Failed to get step duration for step name '{}'".format(step))
                pass
        return step_durations

    def get_step_states(self):
        step_states = OrderedDict()
        for history_item in self._list_data:
            step_name = history_item.step_name
            try:
                step_state = definitions.Ticket_Activity.find_matching_state(history_item.description)
            except ValueError:
                logger.debug("Step: {}, state: '{}'  was not found - ignoring it".format(step_name,
                                                                                         history_item.description))
                continue
            step_states[step_name] = step_state
        return step_states


class Ticket_History_Activity(XML_Object_Base):
    DATE_STRING_LENGTH = 29
    LEGACY_DATE_STRING_LENGTH = 25
    OTHER_DATE_STRING_LENGTH = 24
    OTHER_OTHER_DATE_STRING_LENGTH = 20
    DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%S.%f%z"
    LEGACY_DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%S%z"
    OTHER_DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%S.%fZ"
    OTHER_OTHER_DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self, date, performed_by, description, step_name, task_name):
        self.date = date
        self.performed_by = performed_by
        self.description = description
        self.step_name = step_name
        self.task_name = task_name
        super().__init__(Elements.TICKET_HISTORY_ACTIVITY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        date = get_xml_text_value(xml_node, Elements.DATE)
        performed_by = get_xml_text_value(xml_node, Elements.PERFORMED_BY)
        description = get_xml_text_value(xml_node, Elements.DESCRIPTION)
        step_name = get_xml_text_value(xml_node, Elements.STEP_NAME)
        task_name = get_xml_text_value(xml_node, Elements.TASK_NAME)
        return cls(date, performed_by, description, step_name, task_name)

    def as_time_obj(self):
        time_string = self.date[:-3] + self.date[-2:]
        if len(self.date) == Ticket_History_Activity.DATE_STRING_LENGTH:
            return datetime.datetime.strptime(time_string, Ticket_History_Activity.DATE_FORMAT_STRING)
        elif len(self.date) == Ticket_History_Activity.LEGACY_DATE_STRING_LENGTH:
            return datetime.datetime.strptime(time_string, Ticket_History_Activity.LEGACY_DATE_FORMAT_STRING)
        elif len(self.date) == Ticket_History_Activity.OTHER_DATE_STRING_LENGTH:
            return datetime.datetime.strptime(time_string, Ticket_History_Activity.OTHER_DATE_FORMAT_STRING)
        elif len(self.date) == Ticket_History_Activity.OTHER_OTHER_DATE_STRING_LENGTH:
            return datetime.datetime.strptime(time_string, Ticket_History_Activity.OTHER_OTHER_DATE_FORMAT_STRING)
        else:
            raise ValueError("Unknown date string format: {}".format(self.date))

    def as_time_obj_with_tz(self):
        dt = self.as_time_obj()
        if dt.tzinfo:
            return dt
        else:
            return dt.replace(tzinfo=datetime.timezone.utc)


class Application_Details(Base_Link_Target):
    def __init__(self, app_id, display_name, name, link):
        super().__init__(Elements.APPLICATION_DETAILS, app_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        app_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(app_id, display_name, name, link)


class Comment(XML_Object_Base):
    def __init__(self, comment, comment_tag=Elements.COMMENT):
        self.comment = comment
        super().__init__(comment_tag)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError("from_xml_node must be implemented by derived classes.")


class Reassign_Comment(Comment):
    def __init__(self, comment):
        super().__init__(comment, Elements.REASSIGN_TASK_COMMENT)


class Redo_Comment(Comment):
    def __init__(self, comment):
        super().__init__(comment, Elements.REDO_STEP_COMMENT)


class IpAddress(XML_Object_Base):
    def __init__(self, ip_address):
        self.ip_address = ip_address
        super().__init__(Elements.IP_ADDRESS)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls(xml_node.text)

    def __str__(self):
        return self.ip_address


class ExcludedDevice(Flat_XML_Object_Base, Comparable):
    def __init__(self, device_id):
        self.id = device_id
        super().__init__(xml_tag=Elements.ID, content=device_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls(xml_node.text)

    def __str__(self):
        return str(self.id)

    def __repr__(self):
        return str(self)

    def _key(self):
        return self.id,


class ExcludedDevicesList(XML_List):
    def __init__(self, devices):
        """

        :param devices:
        :type devices: list[int|ExcludedDevice]
        """
        self.excluded_devices = []
        for device in devices:
            if isinstance(device, int):
                self.excluded_devices.append(ExcludedDevice(device))
            elif isinstance(device, ExcludedDevice):
                self.excluded_devices.append(device)
            else:
                raise TypeError("Elements of 'devices' must be of type int or ExcludedDevice")
        super().__init__(Elements.DEVICE_IDS, self.excluded_devices)

    @classmethod
    def from_xml_node(cls, xml_node):
        device_ids = []
        for device_node in xml_node.iter(tag=Elements.ID):
            device_ids.append(ExcludedDevice.from_xml_node(device_node))
        return cls(device_ids)
