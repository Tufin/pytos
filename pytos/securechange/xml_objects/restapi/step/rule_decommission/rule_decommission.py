from pytos.securechange.xml_objects.restapi.step.initialize import *
from pytos.securechange.xml_objects.restapi.step.access_request.designer import DesignerResult
from pytos.securechange.xml_objects.restapi.step.step import Binding, SlimRuleWithMetadata, SlimRule

logger = logging.getLogger(XML_LOGGER_NAME)


class Rule_decommission_Generator:
    """This class is used to generate a SecureChange RuleDecommission from tuple."""

    def __init__(self, revision_id, device_id, bindings, action):
        self.revision_id = revision_id
        self.device_id = device_id
        self.bindings = bindings
        self.action = action

    @classmethod
    def from_dict(cls, rule_decommission_dict):
        """Constructor

        :param rule_decommission_dict: A dict, which consists of (device_id,revision_id,bindings,action).
            device_id is an int
            revision_id is an int
            bindings is a dict: Keys are the bind uid(string) and the values are lists of rules(list of strings)
            action is a string, which can be one of the following:
                1. Disable
                2. Remove
        :type rule_decommission_dict: tuple(int, int, dict{[str]:list[str]}, str)
        """
        device_id = rule_decommission_dict['device_id']
        revision_id = rule_decommission_dict['revision_id']
        bindings = rule_decommission_dict['bindings']
        action = rule_decommission_dict['action']
        return cls(revision_id, device_id, bindings, action)

    def create_devices_bindings(self):
        """Create the Device object for the Rule Decommission ticket.

        :return: The generated Devices list object.
        :rtype: XML_List of devices
        """
        device_bindings = []
        for bind_uid, rules in self.bindings.items():
            bind_rules = []
            for rule_uid in rules:
                bind_rules.append(SlimRule(uid=rule_uid))
            bind_rules = XML_List(Elements.RULES, bind_rules)
            device_bindings.append(RuleDecommissionBinding(binding_uid=bind_uid, rules=bind_rules))

        device_bindings = XML_List(Elements.BINDINGS, device_bindings)
        devices = XML_List(Elements.DEVICES, [RuleDecommissionDevice(revision_id=self.revision_id,
                                                                     management_id=self.device_id,
                                                                     bindings=device_bindings)])
        return devices


class Step_Field_Rule_Decommission(Step_Field_Base):
    def __init__(self, num_id, name, read_only=None, action=None, devices=None, verifier_result=None,
                 designer_result=None):
        self.action = action
        self.devices = devices
        self.verifier_result = verifier_result
        self.designer_result = designer_result
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_RULE_DECOMMISSION)

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
        action = get_xml_text_value(xml_node, Elements.ACTION)
        verifier_node = get_xml_node(xml_node, Elements.VERIFIER_RESULT, True)
        if verifier_node is not None:
            verifier_result = RDVerifier.from_xml_node(verifier_node)
        else:
            verifier_result = None
        designer_node = get_xml_node(xml_node, Elements.DESIGNER_RESULT, True)
        if designer_node is not None:
            designer_result = DesignerResult.from_xml_node(designer_node)
        else:
            designer_result = None

        devices = XML_List.from_xml_node_by_tags(xml_node, Elements.DEVICES, Elements.DEVICE, RuleDecommissionDevice,
                                                 True)
        return cls(num_id, name, read_only, action, devices, verifier_result, designer_result)

    def remove_verifier_result(self):
        """
        Remove verifier result from a rule decommission for a task.
        Need to use it when trying to put rule decommission task with verifier result
        """
        self.verifier_result = None

    def remove_designer_result(self):
        """
        Remove designer result from a rule decommission for a task.
        Need to use it when trying to put rule decommission task with designer result
        """
        self.designer_result = None

    def sanitize_results(self):
        """
        Remove  both designer and verifier result from a rule decommission for a task.
        Need to use it when trying to put rule decommission task with designer result and verifier results
        """
        self.remove_designer_result()
        self.remove_verifier_result()

    def to_pretty_str(self):
        action_str = "Action: {}".format(self.action)
        devices_str = '\n'.join(device.to_pretty_str() for device in self.devices)
        return '\n\n'.join((action_str, devices_str))


class RuleDecommissionDevice(XML_Object_Base):
    """This class represents the RuleDecommissionDeviceDTO used in rule decommission field"""

    def __init__(self, revision_id, management_id, bindings, management_ip=None, revision_number=None,
                 number_of_rules=None, administrator=None, management_name=None):
        self.revision_id = revision_id
        self.management_id = management_id
        self.bindings = bindings
        self.management_ip = management_ip
        self.revision_number = revision_number
        self.number_of_rules = number_of_rules
        self.administrator = administrator
        self.management_name = management_name
        super().__init__(Elements.DEVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        revision_id = get_xml_text_value(xml_node, Elements.REVISION_ID)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        bindings = XML_List.from_xml_node_by_tags(xml_node, Elements.BINDINGS, Elements.BINDING,
                                                  RuleDecommissionBinding)
        management_ip = get_xml_text_value(xml_node, Elements.MANAGEMENT_IP)
        revision_number = get_xml_int_value(xml_node, Elements.REVISION_NUMBER)
        number_of_rules = get_xml_int_value(xml_node, Elements.NUMBER_OF_RULES)
        administrator = get_xml_text_value(xml_node, Elements.ADMINISTRATOR)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        return cls(revision_id, management_id, bindings, management_ip, revision_number, number_of_rules, administrator,
                   management_name)

    def to_pretty_str(self):
        bindings_info = "\n".join(binding.to_pretty_str() for binding in self.bindings)
        return "Device name: {}\n{}".format(self.management_name, bindings_info)


class RDVerifier(XML_Object_Base):
    """This class represents the RDVerifier used in rule decommission field"""

    def __init__(self, result, reason, message, status):
        self.result = result
        self.reason = reason
        self.message = message
        self.status = status
        super().__init__(Elements.VERIFIER_RESULT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        status = get_xml_text_value(xml_node, Elements.STATUS)
        reason = get_xml_text_value(xml_node, Elements.REASON)
        message = get_xml_text_value(xml_node, Elements.MESSAGE)

        result = get_xml_node(xml_node, Elements.RESULT, True)
        if result is not None:
            result = ReferenceURL.from_xml_node(result)
        return cls(result, reason, message, status)


class RuleDecommissionBinding(XML_Object_Base):
    """This class represents the RuleDecommissionBindingDTO used in rule decommission field"""

    def __init__(self, binding_uid, rules, binding=None):
        self.binding_uid = binding_uid
        self.rules = rules
        if binding is not None:
            self.binding = binding
        super().__init__(Elements.BINDING)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        binding_uid = get_xml_text_value(xml_node, Elements.BINDING_UID)
        rules = XML_List.from_xml_node_by_tags(xml_node, Elements.RULES, Elements.RULE, SlimRuleWithMetadata)
        binding_node = get_xml_node(xml_node, Elements.BINDING, True)
        if binding_node is not None:
            binding = Binding.from_xml_node(binding_node)
        else:
            binding = None
        return cls(binding_uid, rules, binding)

    def to_pretty_str(self):
        return '\n'.join(rule.to_pretty_str() for rule in self.rules)
