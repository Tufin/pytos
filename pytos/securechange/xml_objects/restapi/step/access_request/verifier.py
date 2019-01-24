from pytos.securechange.xml_objects.restapi.step.initialize import *
from pytos.securechange.xml_objects.restapi.step.step import AbsNetwork, AbsService, Binding

logger = logging.getLogger(XML_LOGGER_NAME)


class Analysis_Result(XML_Object_Base):
    IMPLEMENTED = "implemented"
    NOT_AVAILABLE = "not available"
    NOT_IMPLEMENTED = "not implemented"
    NOT_RUN = "not run"
    VERIFIED = "verified"

    def __init__(self, xml_tag, status):
        self.status = status
        super().__init__(xml_tag)

    def is_not_run(self):
        if self.status == Analysis_Result.NOT_RUN:
            return True
        else:
            return False

    def is_not_available(self):
        if self.status == Analysis_Result.NOT_AVAILABLE:
            return True
        else:
            return False

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError(
                "from_xml_node must be implemented by derived classes.")


class Verifier_Result(Analysis_Result):
    """This class represents the Verifier DTO"""

    def __init__(self, status, result):
        self.status = status
        if result:
            self.result = result
        super().__init__(Elements.VERIFIER_RESULT, status)

    def is_implemented(self):
        return self.status == Verifier_Result.IMPLEMENTED

    def is_verified(self):
        return self.status == Verifier_Result.VERIFIED

    def is_not_implemented(self):
        return self.status == Verifier_Result.NOT_IMPLEMENTED

    def is_not_run(self):
        return self.status == Verifier_Result.NOT_RUN

    def is_not_available(self):
        return self.status == Verifier_Result.NOT_AVAILABLE

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


class AccessRequestVerifierResult(XML_Object_Base):
    """The class represents the expended verifier results """

    def __init__(self, verifier_targets):
        self.verifier_targets = verifier_targets
        super().__init__(Elements.ACCESS_REQUEST_VERIFIER_RESULT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """

        verifier_targets = XML_List.from_xml_node_by_tags(xml_node, Elements.VERIFIER_TARGETS,
                                                          Elements.VERIFIER_TARGET, VerifierTarget)
        return cls(verifier_targets)


class VerifierTarget(XML_Object_Base):
    """This class represents the VerifierDeviceDTO"""

    def __init__(self, management_name, managementId, device_type, revision_number, administrator,
                 date, time, vendor, verification_status, verifier_bindings, verifier_warning):
        self.management_name = management_name
        self.managementId = managementId
        self.device_type = device_type
        self.revision_number = revision_number
        self.administrator = administrator
        self.date = date
        self.time = time
        self.vendor = vendor
        self.verification_status = verification_status
        self.verifier_bindings = verifier_bindings
        self.verifier_warning = verifier_warning
        super().__init__(Elements.VERIFIER_TARGET)

    def to_pretty_str(self):
        verifier_string = "Managment name: {}\n".format(self.management_name)
        verifier_string += "Revision Number: {}\n".format(self.revision_number)
        verifier_string += "Date: {}\n".format(self.date)
        verifier_string += "Administrator: {}\n".format(self.administrator)
        verifier_string += "Status: {}\n".format(self.verification_status)
        verifier_string += "\n\n"
        for verifier_binding in self.verifier_bindings:
            for element, value in verifier_binding.binding.__dict__.items():
                if element.startswith('_'):
                    continue
                verifier_string += "{}: {}\n\n".format(element.capitalize(), value)

            percent = verifier_binding.percent_implemented
            stat = "Implemented ({}%)\n\n".format(percent) if percent else "Not Implemented ({}%)\n\n".format(percent)
            verifier_string += "Status: {}".format(stat)

            verifier_string += "Violating Rules: "
            violating_rule_string = ''
            for violating_rule in verifier_binding.violating_rules:
                violating_rule_string += "\n\tSources: {}".format(violating_rule.src_networks.display_name)
                violating_rule_string += "\n\tDestinations: {}".format(violating_rule.dst_networks.display_name)
            if not violating_rule_string:
                msg = "The queried traffic is handled by the implicit cleanup rule."
                verifier_string += "---" if self.verification_status.lower() == "implemented" else msg
            else:
                verifier_string += violating_rule_string
            verifier_string += "\n\n"

            verifier_string += "Implementing Rules: "
            implementing_rule_string = ''
            for implementing_rule in verifier_binding.implementing_rules:
                implementing_rule_string += "\n\tSources: {}/{}".format(implementing_rule.src_networks.ip,
                                                                        implementing_rule.src_networks.subnet_mask)
                implementing_rule_string += "\n\tDestinations: {}/{}".format(implementing_rule.dst_networks.ip,
                                                                             implementing_rule.dst_networks.subnet_mask)
                implementing_rule_string += "\n\tServices: {}".format(implementing_rule.dst_service.name)
            if not implementing_rule_string:
                verifier_string += "--------"
            else:
                verifier_string += implementing_rule_string
            verifier_string += "\n\n-----------------------------------------------------------\n\n\n"
        verifier_string += "\n"
        return verifier_string

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        device_type = get_xml_text_value(xml_node, Elements.DEVICE_TYPE)
        revision_number = get_xml_int_value(xml_node, Elements.REVISION_NUMBER)
        administrator = get_xml_text_value(xml_node, Elements.ADMINISTRATOR)
        date = get_xml_text_value(xml_node, Elements.DATE)
        time = get_xml_text_value(xml_node, Elements.TIME)
        vendor = get_xml_text_value(xml_node, Elements.VENDOR)
        verifier_warning = get_xml_text_value(xml_node, Elements.VERIFIER_WARNING)
        verification_status = get_xml_text_value(xml_node, Elements.VERIFICATION_STATUS)
        verifier_bindings = XML_List.from_xml_node_by_tags(xml_node, Elements.VERIFIER_BINDINGS,
                                                           Elements.VERIFIER_BINDING, VerifierBinding)
        return cls(management_name, management_id, device_type, revision_number, administrator,
                   date, time, vendor, verification_status, verifier_bindings, verifier_warning)


class VerifierBinding(XML_Object_Base):
    """This class represents the VerifierBindingDTO"""

    def __init__(self, handled_by_implicit_cleanup_rule, percent_implemented, implementing_rules,
                 implementation_percentage_threshold, verified, verifier_warning, violating_rules, binding):
        self.handled_by_implicit_cleanup_rule = handled_by_implicit_cleanup_rule
        self.percent_implemented = percent_implemented
        self.implementing_rules = implementing_rules
        self.implementation_percentage_threshold = implementation_percentage_threshold
        self.verified = verified
        self.verifier_warning = verifier_warning
        self.violating_rules = violating_rules
        self.binding = binding
        super().__init__(Elements.VERIFIER_BINDING)

    @classmethod
    def from_xml_node(cls, xml_node):
        handled_by_implicit_cleanup_rule = get_xml_text_value(xml_node, Elements.HANDLE_IMPLICIT_CLEANUP_RULE)
        percent_implemented = get_xml_text_value(xml_node, Elements.PERCENT_IMPLEMENTED)
        implementation_percentage_threshold = get_xml_text_value(xml_node, Elements.IMPLEMENTATION_PERCENTAGE_THRESHOLD)
        verified = get_xml_text_value(xml_node, Elements.VERIFIED)
        verifier_warning = get_xml_text_value(xml_node, Elements.VERIFIER_WARNING)
        violating_rules = XML_List.from_xml_node_by_tags(xml_node, Elements.VIOLATING_RULES,
                                                         Elements.VIOLATING_RULE, ViolatingRule)
        implementing_rules = XML_List.from_xml_node_by_tags(xml_node, Elements.IMPLEMENTING_RULES,
                                                            Elements.IMPLEMENTING_RULE, ImplementingRule)
        binding = Binding.from_xml_node(get_xml_node(xml_node, Elements.BINDING))
        return cls(handled_by_implicit_cleanup_rule, percent_implemented, implementing_rules,
                   implementation_percentage_threshold, verified, verifier_warning, violating_rules, binding)


class SlimRuleObject(XML_Object_Base):
    """This class represents the SlimRuleDTO"""

    def __init__(self, xml_node, target_type_tag):
        self.rule_number = get_xml_text_value(xml_node, Elements.RULENUMBER)
        self.dst_networks = SlimRuleObject.get_obj(AbsNetwork, xml_node, Elements.DESTNETWORKS)
        self.src_networks = SlimRuleObject.get_obj(AbsNetwork, xml_node, Elements.SOURCENETWORKS)
        self.src_service = SlimRuleObject.get_obj(AbsService, xml_node, Elements.SOURCESERVICES)
        self.dst_service = SlimRuleObject.get_obj(AbsService, xml_node, Elements.DESTINATIONSERVICES)
        self.action = get_xml_text_value(xml_node, Elements.ACTION)
        self.comment = get_xml_text_value(xml_node, Elements.COMMENT)
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        super().__init__(target_type_tag)

    @staticmethod
    def get_obj(cls, xml_node, element):
        logger.debug("Findign the element '{}' in the XML".format(element))
        node = get_xml_node(xml_node, element, True)
        logger.debug("The node '{}' was found".format(node))
        if node is None:
            obj = Flat_XML_Object_Base(element)
        else:
            obj = cls.from_xml_node(node)
        return obj


class ImplementingRule(SlimRuleObject):
    """This class represents the implementing_rule element in the VerifierBindingDTO"""

    def __init__(self, xml_node):
        super().__init__(xml_node, Elements.IMPLEMENTING_RULE)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls(xml_node)


class ViolatingRule(SlimRuleObject):
    """This class represents the violating_rule element in the VerifierBindingDTO"""

    def __init__(self, xml_node):
        super().__init__(xml_node, Elements.VIOLATING_RULE)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls(xml_node)

