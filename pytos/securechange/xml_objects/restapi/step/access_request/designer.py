
import enum

from pytos.securechange.xml_objects.restapi.step.access_request.initialize import *

logger = logging.getLogger(XML_LOGGER_NAME)


class DesignerInstructionType(enum.Enum):
    NewRule = "NEW_RULE"
    AddObjectToDevice = "ADD_OBJECT_TO_DEVICE"
    FullyImplemented = "FULLY_IMPLEMENTED"
    NA = "NA"

class DesignerInstructionStatus(enum.Enum):
    Success = "DESIGN_SUCCESS"
    FullyImplemented = "DESIGN_FULLY_IMPLEMENTED"
    Failed = "DESIGN_FAILED"

class DesignerResult(XML_Object_Base):
    """This class represents the Designer Result element in the access request"""
    IMPLEMENTED_FAILURE = "implementation failure"
    DESIGNER_SUCCESS = "designer success"
    IMPLEMENTED = "implemented"
    DESIGNER_CANNOT_COMPUTE = "designer cannot compute"

    def __init__(self, status, result):
        self.status = status
        self.result = result
        super().__init__(Elements.DESIGNER_RESULT)

    def is_success(self):
        return self.status == DesignerResult.DESIGNER_SUCCESS

    def is_implemented(self):
        return self.status != DesignerResult.IMPLEMENTED_FAILURE

    def get_result_url(self):
        if self.result is None:
            return None
        return self.result._url

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        status = get_xml_text_value(xml_node, Elements.STATUS)
        result = get_xml_node(xml_node, Elements.RESULT, True)
        if result is not None:
            result = ReferenceURL.from_xml_node(result)
        return cls(status, result)


class DesignerResults(XML_Object_Base):
    def __init__(self, device_suggestion):
        self.device_suggestion = device_suggestion
        super().__init__(Elements.DESIGNER_RESULTS)

    def is_implemented(self):
        for device_suggestion in self.device_suggestion:
            push_status = device_suggestion.is_pushed()
            if push_status is None:
                for suggestion_per_binding in device_suggestion.suggestions_per_binding:
                    for instruction in suggestion_per_binding.instructions:
                        if not instruction.is_fully_implemented():
                            return False
                    return True
            elif not push_status:
                return False
        return True

    def __str__(self):
        device_list = []
        for device_suggestion in self.device_suggestion:
            # device_str = device_suggestion.to_pretty_str()
            binding_list = []
            for binding in device_suggestion.suggestions_per_binding:
                instruction_list = []
                for instruction in binding.instructions:
                    instruction_list.append(str(instruction))
                binding_list.append('{}; {}'.format(str(binding), ','.join(instruction_list)))
            device_list.append('{}; {}'.format(str(device_suggestion), ','.join(binding_list)))
        return '\n'.join(device_list)

    @classmethod
    def from_xml_node(cls, xml_node):
        args = (xml_node, Elements.SUGGESTIONS_PER_DEVICE, Elements.DEVICE_SUGGESTION, DesignerDeviceSuggestions)
        device_suggestion = XML_List.from_xml_node_by_tags(*args)
        return cls(device_suggestion)


class DesignerDeviceSuggestions(XML_Object_Base):
    PUSH_SUCCESS_STATUS = "Device update succeeded"

    def __init__(self, id, management_name, management_id, vendor_name, revision_number, offline_device,
                 ancestor_management_id, ancestor_management_name, ancestor_management_revision_id, push_status,
                 change_id, designer_commands, suggestions_per_binding):
        self.id = id
        self.management_name = management_name
        self.management_id = management_id
        self.vendor_name = vendor_name
        self.revision_number = revision_number
        self.offline_device = offline_device
        self.ancestor_management_id = ancestor_management_id
        self.ancestor_management_name = ancestor_management_name
        self.ancestor_management_revision_id = ancestor_management_revision_id
        self.push_status = push_status
        self.change_id = change_id
        self.designer_commands = designer_commands
        self.suggestions_per_binding = suggestions_per_binding
        super().__init__(Elements.DEVICE_SUGGESTION)

    def __str__(self):
        return "Device Name: {}".format(self.management_name)

    def is_pushed(self):
        if self.push_status is not None:
            if self.push_status == DesignerDeviceSuggestions.PUSH_SUCCESS_STATUS:
                return True
            return False

    @classmethod
    def from_xml_node(cls, xml_node):
        id = get_xml_int_value(xml_node, Elements.ID)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        vendor_name = get_xml_text_value(xml_node, Elements.VENDOR_NAME)
        revision_number = get_xml_int_value(xml_node, Elements.REVISION_NUMBER)
        offline_device = get_xml_text_value(xml_node, Elements.OFFLINE_DEVICE)
        ancestor_management_id = get_xml_int_value(xml_node, Elements.ANCESTOR_MANAGEMENT_ID)
        ancestor_management_name = get_xml_text_value(xml_node, Elements.ANCESTOR_MANAGEMENT_NAME)
        ancestor_management_revision_id = get_xml_int_value(xml_node, Elements.ANCESTOR_MANAGEMENT_REVISION_ID)
        push_status = get_xml_text_value(xml_node, Elements.PUSH_STATUS)
        change_id = get_xml_text_value(xml_node, Elements.CHANGE_ID)
        #TODO: Need to implement designer commands
        # designer_commands = XML_List.from_xml_node_by_tags(xml_node, Elements.DESIGNER_COMMANDS,
        #                                                    Elements.DESIGNER_COMMANDS,
        #                                                    DesignerPersistedCommand)
        suggestions_per_binding = XML_List.from_xml_node_by_tags(xml_node, Elements.SUGGESTIONS_PER_BINDING,
                                                                 Elements.BINDING_SUGGESTION,
                                                                 DesignerBindingSuggestion)
        designer_commands = None
        return cls(id, management_name, management_id, vendor_name, revision_number, offline_device,
                   ancestor_management_id, ancestor_management_name, ancestor_management_revision_id, push_status,
                   change_id, designer_commands, suggestions_per_binding)


class DesignerPersistedCommand(XML_Object_Base):
    def __init__(self):
        super().__init__(Elements.DESIGNER_COMMAND)

    @classmethod
    def from_xml_node(cls, xml_node):
        pass


class DesignerBindingSuggestion(XML_Object_Base):
    def __init__(self, id, binding_uid, binding_name, instructions):
        self.id = id
        self.binding_uid = binding_uid
        self.binding_name = binding_name
        self.instructions = instructions
        super().__init__(Elements.BINDING_SUGGESTION)

    def __str__(self):
        return "Binding Name: {}".format(self.binding_name)

    @classmethod
    def from_xml_node(cls, xml_node):
        id = get_xml_int_value(xml_node, Elements.ID)
        binding_uid = get_xml_text_value(xml_node, Elements.BINDING_UID)
        binding_name = get_xml_text_value(xml_node, Elements.BINDING_NAME)
        instructions = XML_List.from_xml_node_by_tags(xml_node,
                                                      Elements.INSTRUCTIONS,
                                                      Elements.INSTRUCTION,
                                                      DesignerInstruction)
        return cls(id, binding_uid, binding_name, instructions)


class DesignerInstruction(XML_Object_Base):

    def __init__(self, id, implements_access_requests, status, instruction, instruction_type, modified_object_name,
                 device_added_network_object):
        self.id = id
        self.implements_access_requests = implements_access_requests
        self.status = status
        self.instruction = instruction
        self.instruction_type = instruction_type
        self.modified_object_name = modified_object_name
        self.device_added_network_object = device_added_network_object
        super().__init__(Elements.INSTRUCTION)

    def is_fully_implemented(self):
        return self.status.upper().strip() == DesignerInstructionStatus.FullyImplemented.value

    def __str__(self):
        output = "AR: {}, Status: {}, Instruction: {}"
        return output.format(self.implements_access_requests.order, self.status, self.instruction)

    @classmethod
    def from_xml_node(cls, xml_node):
        id = get_xml_int_value(xml_node, Elements.ID)
        # implements_access_requests = Flat_XML_Object_Base(Elements.ORDER, None,
        #                                                   get_xml_text_value(xml_node, Elements.ORDER))
        implements_access_requests_node = get_xml_node(xml_node, Elements.IMPLEMENTS_ACCESS_REQUESTS)
        implements_access_requests = ImplementsAccessRequest.from_xml_node(implements_access_requests_node)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        instruction = get_xml_text_value(xml_node, Elements.INSTRUCTION)
        instruction_type = get_xml_text_value(xml_node, Elements.INSTRUCTION_TYPE)
        modified_object_name = get_xml_text_value(xml_node, Elements.MODULES_AND_POLICY)
        #TODO: Need to implementthe device add network object
        device_added_network_object = None
        return cls(id, implements_access_requests, status, instruction, instruction_type, modified_object_name,
                   device_added_network_object)


class ImplementsAccessRequest(XML_Object_Base):
    def __init__(self, order):
        self.order = order
        super().__init__(Elements.IMPLEMENTS_ACCESS_REQUESTS)

    @classmethod
    def from_xml_node(cls, xml_node):
        order = get_xml_text_value(xml_node, Elements.ORDER)
        return cls(order)