
from pytos.securechange.xml_objects.restapi.step.access_request.initialize import *

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
        managementId = get_xml_int_value(xml_node, Elements.MANAGEMENTID)
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
        return cls(management_name, managementId, device_type, revision_number, administrator,
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
        self.dst_networks = SlimRuleObject.get_obj(VerifierNetwork, xml_node, Elements.DESTNETWORKS)
        self.src_networks = SlimRuleObject.get_obj(VerifierNetwork, xml_node, Elements.SOURCENETWORKS)
        self.src_service = SlimRuleObject.get_obj(VerifierService, xml_node, Elements.SOURCESERVICES)
        self.dst_service = SlimRuleObject.get_obj(VerifierService, xml_node, Elements.DESTINATIONSERVICES)
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


class VerifierNetwork(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base class for parsing all network object"""

    @classmethod
    def from_xml_node(cls, xml_node):
        try:
            verifier_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[verifier_type](xml_node)
            except KeyError:
                logger.error('Unknown violation object type "{}"'.format(verifier_type))


class NetworkObject(VerifierNetwork):
    """Base class for all sub type of the network object"""

    def __init__(self, xml_node, element):
        self.address_book = get_xml_text_value(xml_node, Elements.ADDRESS)
        self.type_on_device = get_xml_text_value(xml_node, Elements.TYPE)
        self.version_id = get_xml_int_value(xml_node, Elements.VERSION_ID)
        self.referenced = get_xml_text_value(xml_node, Elements.REFERENCED)
        interface_name = get_xml_text_value(xml_node, Elements.INTERFACE_NAME)
        self.nat_info = type('NatInfo', (), {'interface_name': interface_name})()
        self.installable_target = get_xml_text_value(xml_node, Elements.INSTALLABLE_TARGET)
        self.group_id = get_xml_text_value(xml_node, Elements.GROUP_ID)
        self.device_type = get_xml_text_value(xml_node, Elements.DEVICE_TYPE)
        self.ip_type = get_xml_text_value(xml_node, Elements.IP_TYPE)
        self.id = get_xml_text_value(xml_node, Elements.ID)
        self.zone = PolicyZone(xml_node)
        self.device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        self.admin_domain = AdminDomain(xml_node)
        self.inDomainElementId = get_xml_text_value(xml_node, Elements.INDOMAINELEMENTID)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.origin = get_xml_text_value(xml_node, Elements.ORIGIN)
        self.comment = get_xml_text_value(xml_node, Elements.COMMENT)
        self.shared = get_xml_text_value(xml_node, Elements.SHARED)
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        self.implicit = get_xml_text_value(xml_node, Elements.IMPLICIT)
        self.class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        self.display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        self.uid = get_xml_text_value(xml_node, Elements.UID)
        super().__init__(element)


class AnyNetworkObject(NetworkObject):
    """The class represents the any_network_object"""
    class_identifier = Attributes.VIOLATION_ANY_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_NETWORK_OBJECT)


class HostNetworkObject(NetworkObject):
    """The class represents the host_network_object"""
    class_identifier = Attributes.HOST_NETWORK_OBJECT

    def __init__(self, xml_node):
        self.subnet_mask = get_xml_text_value(xml_node, Elements.SUBNET_MASK)
        self.ip = get_xml_text_value(xml_node, Elements.IP)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.HOST_NETWORK_OBJECT)


class SubnetNetworkObject(NetworkObject):
    """The class represents the subnet_network_object"""
    class_identifier = Attributes.SUBNET_NETWORK_OBJECT

    def __init__(self, xml_node):
        self.subnet_mask = get_xml_text_value(xml_node, Elements.SUBNET_MASK)
        self.ip = get_xml_text_value(xml_node, Elements.IP)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.SUBNET_NETWORK_OBJECT)


class VerifierService(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base class for parsing all services objects"""

    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            verifier_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[verifier_type](xml_node)
            except KeyError:
                logger.error('Unknown violation object type "{}"'.format(verifier_type))


class Service(VerifierService):
    """Base class for all sub type of the services objects"""

    def __init__(self, xml_node, element):
        self.version_id = get_xml_text_value(xml_node, Elements.VERSION_ID)
        self.referenced = get_xml_text_value(xml_node, Elements.REFERENCED)
        self.match_rule = get_xml_text_value(xml_node, Elements.MATCH_RULE)
        self.id = get_xml_text_value(xml_node, Elements.ID)
        self.device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        self.admin_domain = AdminDomain(xml_node)
        self.in_domain_element_id = get_xml_text_value(xml_node, Elements.INDOMAINELEMENTID)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.origin = get_xml_text_value(xml_node, Elements.ORIGIN)
        self.comment = get_xml_text_value(xml_node, Elements.COMMENT)
        self.shared = get_xml_text_value(xml_node, Elements.SHARED)
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        self.implicit = get_xml_text_value(xml_node, Elements.IMPLICIT)
        self.class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        self.display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        self.uid = get_xml_text_value(xml_node, Elements.UID)
        super().__init__(element)


class AnyService(Service):
    """The class represents the any_service_object"""
    class_identifier = Attributes.VIOLATION_ANY_SERVICE

    def __init__(self, xml_node):
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        self.min_protocol = get_xml_int_value(xml_node, Elements.MIN_PROTOCOL)
        self.max_protocol = get_xml_int_value(xml_node, Elements.MAX_PROTOCOL)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_SERVICE)


class TransportService(Service):
    """The class represents the transport_service_object"""
    class_identifier = Attributes.TRANSPORT_SERVICE

    def __init__(self, xml_node):
        self.cp_inspect_streaming_name = get_xml_text_value(xml_node, Elements.CP_INSPECT_STREAMING_NAME)
        self.min_protocol = get_xml_int_value(xml_node, Elements.MIN_PROTOCOL)
        self.max_protocol = get_xml_int_value(xml_node, Elements.MAX_PROTOCOL)
        self.protocol = get_xml_int_value(xml_node, Elements.PROTOCOL)
        self.min_value_source = get_xml_int_value(xml_node, Elements.MIN_VALUE_SOURCE)
        self.max_value_source = get_xml_int_value(xml_node, Elements.MAX_VALUE_SOURCE)
        self.cp_prototype_name = get_xml_text_value(xml_node, Elements.CP_PROTOTYPE_NAME)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.TRANSPORT_SERVICE)


class Binding(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base Binding Class that handles all Binding sub Binding DTO parsing"""

    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            binding_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[binding_type](xml_node)
            except KeyError:
                logger.error('Unknown binding object type "{}"'.format(binding_type))

    def get_binding_info(self):
        raise NotImplemented


class AclBinding(Binding):
    """The class represents the acl_binding_object which is sub type of Binding_DTO"""
    class_identifier = Attributes.ACL__BINDING

    def __init__(self, xml_node):
        self.acl_name = get_xml_text_value(xml_node, Elements.ACL_NAME)

        self.incoming_interface_names = [node.text for node in xml_node.iter(Elements.INCOMING_INTERFACE_NAME)]
        self.outgoing_interface_names = [node.text for node in xml_node.iter(Elements.OUTGOING_INTERFACE_NAME)]

        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.ACL__BINDING)

    def get_binding_info(self):
        print([attr for attr in dir(self) if not callable(getattr(self,attr)) and not attr.startswith("__")])
        return {"acl_name": self.acl_name,
                "incoming_interface_name": self.incoming_interface_name,
                "outgoing_interface_name": self.outgoing_interface_name}


class ZoneBinding(Binding):
    """The class represents the zone_binding object which is sub type of Binding_DTO"""
    class_identifier = Attributes.ZONE__BINDING

    def __init__(self, xml_node):
        self.from_zone = get_xml_text_value(xml_node, Elements.FROM_ZONE)
        self.to_zone = get_xml_text_value(xml_node, Elements.TO_ZONE)
        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.ZONE__BINDING)

    def get_binding_info(self):
        return {"from_zone": self.from_zone,
                "to_zone": self.to_zone
                }


class PolicyBinding(Binding):
    class_identifier = Attributes.POLICY__BINDING

    def __init__(self, xml_node):
        self.policy_name = get_xml_text_value(xml_node, Elements.POLICY_NAME)
        self.installed_on_module = get_xml_text_value(xml_node, Elements.INSTALLED_ON_MODULE)
        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.POLICY__BINDING)

    def get_binding_info(self):
        return {"policy_name": self.policy_name,
                "installed_on_module": self.installed_on_module
                }

class PolicyZone(XML_Object_Base):
    """The class represents the PolicyZoneDTO"""

    def __init__(self, xml_node):
        self.zone_name_in_parent = get_xml_text_value(xml_node, Elements.ZONE_NAME_IN_PARENT)
        self.address_book = get_xml_text_value(xml_node, Elements.ADDRESS_BOOK)
        self.version_id = get_xml_int_value(xml_node, Elements.VERSION_ID)
        self.admin_domain = AdminDomain(xml_node)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        super().__init__(Elements.ZONE)


class AdminDomain(XML_Object_Base):
    """The class represents the AdminDomainDTO"""

    def __init__(self, xml_node):
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        self.uid = get_xml_text_value(xml_node, Elements.UID)
        super().__init__(Elements.ADMIN_DOMAIN)
