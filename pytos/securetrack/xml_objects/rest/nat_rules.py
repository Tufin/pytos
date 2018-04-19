import logging

from pytos.common.base_types import XML_List, XML_Object_Base, Comparable
from pytos.common.definitions.xml_tags import Elements
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.functions import get_xml_int_value, get_xml_text_value, get_xml_node, create_tagless_xml_objects_list, str_to_bool
from pytos.securetrack.xml_objects.base_types import Base_Object


logger = logging.getLogger(XML_LOGGER_NAME)


class NatRules(XML_List):
    def __init__(self, nat_rules):
        super().__init__(Elements.NAT_RULES, nat_rules)

    @classmethod
    def from_xml_node(cls, xml_node):
        rules = []
        for nat_rule in xml_node.iter(tag=Elements.NAT_RULE):
            rules.append(NatRule.from_xml_node(nat_rule))
        return cls(rules)


class NatRule(XML_Object_Base, Comparable):
    def __init__(self, binding ,num_id, order, uid, auto_nat, disabled, dst_nat_method, enable_net4tonet6, enable_route_lookup,
                 orig_dst_network, orig_service, orig_src_network, egress_interface, rule_number, service_nat_method,
                 src_nat_method, translated_service, translated_dst_network, translated_src_network, nat_type):
        self.binding = binding
        self.id = num_id
        self.order = order
        self.uid = uid
        self.autoNat = auto_nat
        self.disabled = disabled
        self.dstNatMethod = dst_nat_method
        self.enable_net4tonet6 = enable_net4tonet6
        self.enable_route_lookup = enable_route_lookup
        self.orig_dst_network = orig_dst_network
        self.orig_service = orig_service
        self.orig_src_network = orig_src_network
        self.egress_interface = egress_interface
        self.ruleNumber = rule_number
        self.serviceNatMethod = service_nat_method
        self.srcNatMethod = src_nat_method
        self.translated_service = translated_service
        self.translated_dst_network = translated_dst_network
        self.translated_src_network = translated_src_network
        self.type = nat_type
        super().__init__(Elements.NAT_RULE)

    def _key(self):
        hash_keys = [self.id, self.uid]
        if self.binding:
            try:
                hash_keys.append(self.binding.uid)
            except AttributeError:
                pass
        return tuple(hash_keys)

    def __str__(self):
        return "ORIGINAL: (src={} dst={} srv={}); TRANSLATED: (src={} dst={} srv={})".format(
            self.orig_src_network,
            self.orig_dst_network,
            self.orig_service,
            self.translated_src_network,
            self.translated_dst_network,
            self.translated_service
        )

    def is_enabled(self):
        return str_to_bool(self.disabled)

    @classmethod
    def from_xml_node(cls, xml_node):
        num_id = get_xml_int_value(xml_node, Elements.ID)
        order = get_xml_text_value(xml_node, Elements.ORDER)
        uid = get_xml_text_value(xml_node, Elements.UID)
        auto_nat = get_xml_text_value(xml_node, Elements.AUTONAT)
        disabled = get_xml_text_value(xml_node, Elements.DISABLED)
        dst_nat_method = get_xml_text_value(xml_node, Elements.DST_NAT_METHOD)
        enable_net4tonet6 = get_xml_text_value(xml_node, Elements.ENABLE_NET_4_TO_NET_6)
        enable_route_lookup = get_xml_text_value(xml_node, Elements.ENABLE_ROUTE_LOOKUP)
        rule_number = get_xml_text_value(xml_node, Elements.RULENUMBER)
        service_nat_method = get_xml_text_value(xml_node, Elements.SERVICENATMETHOD)
        src_nat_method = get_xml_text_value(xml_node, Elements.SRCNATMETHOD)
        nat_type = get_xml_text_value(xml_node, Elements.TYPE)
        binding = create_tagless_xml_objects_list(xml_node, Elements.BINDING, NatRuleBinding)[0]
        orig_dst_network = create_tagless_xml_objects_list(xml_node, Elements.ORIG_DST_NETWORK, OrigDstNetwork)[0]
        orig_service = create_tagless_xml_objects_list(xml_node, Elements.ORIG_SERVICE, OrigService)[0]
        orig_src_network = create_tagless_xml_objects_list(xml_node, Elements.ORIG_SRC_NETWORK, OrigSrcNetwork)[0]
        egress_interface_node = get_xml_node(xml_node, Elements.ENGRESS_INTERFACE)
        egress_interface = EgressInterface.from_xml_node(egress_interface_node) if egress_interface_node else None
        translated_service = create_tagless_xml_objects_list(xml_node, Elements.TRANSLATED_SERVICE, TranslatedService)[0]
        translated_dst_network = create_tagless_xml_objects_list(xml_node, Elements.TRANSLATED_DST_NETWORK, TranslatedDstNetwork)[0]
        translated_src_network = create_tagless_xml_objects_list(xml_node, Elements.TRANSLATED_SRC_NETWORK, TranslatedSrcNetwork)[0]

        return cls(binding ,num_id, order, uid, auto_nat, disabled, dst_nat_method, enable_net4tonet6, enable_route_lookup,
                 orig_dst_network, orig_service, orig_src_network, egress_interface, rule_number, service_nat_method,
                 src_nat_method, translated_service, translated_dst_network, translated_src_network, nat_type)


class NatRuleBinding(XML_Object_Base):
    def __init__(self, default, postnat_iface, prenat_iface, rule_count, security_rule_count, uid):
        self.default = default
        self.postnat_iface = postnat_iface
        self.prenat_iface = prenat_iface
        self.rule_count = rule_count
        self.security_rule_count = security_rule_count
        self.uid = uid
        super().__init__(Elements.BINDING)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        default = get_xml_text_value(xml_node, Elements.DEFAULT)
        postnat_iface = get_xml_text_value(xml_node, Elements.POSTNAT_IFACE)
        prenat_iface = get_xml_text_value(xml_node, Elements.PRENAT_IFACE)
        rule_count = get_xml_text_value(xml_node, Elements.RULE_COUNT)
        security_rule_count = get_xml_text_value(xml_node, Elements.SECURITY_RULE_COUNT)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(default, postnat_iface, prenat_iface, rule_count, security_rule_count, uid)


class OrigDstNetwork(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.ORIG_DST_NETWORK, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class OrigService(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.DST_SERVICE, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class OrigSrcNetwork(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.ORIG_SRC_NETWORK, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class TranslatedService(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.TRANSLATED_SERVICE, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class TranslatedSrcNetwork(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.TRANSLATED_SRC_NETWORK, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class TranslatedDstNetwork(Base_Object):
    def __init__(self, id, uid, display_name, name, dm_inline_members):
        super().__init__(Elements.TRANSLATED_DST_NETWORK, name, display_name, id, uid)
        if dm_inline_members is not None:
            self.dm_inline_members = dm_inline_members

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        dm_inline_members_node = get_xml_node(xml_node, Elements.DM_INLINE_MEMBRES, True)
        if dm_inline_members_node:
            dm_inline_members = XML_List.from_xml_node_by_tags(xml_node, Elements.DM_INLINE_MEMBRES, Elements.MEMBER,
                                                               DmInlineMember)
        else:
            dm_inline_members = None
        return cls(id, uid, display_name, name, dm_inline_members)


class DmInlineMember(Base_Object):
    def __init__(self, id, uid, display_name, name):
        super().__init__(Elements.MEMBER, name, display_name, id, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        id = get_xml_int_value(xml_node, Elements.ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(id, uid, display_name, name)


class EgressInterface(XML_Object_Base):
    def __init__(self, name, id, direction, device_id, acl_name, is_global, interface_ips):
        self.name = name
        self.id = id
        self.direction = direction
        self.device_id = device_id
        self.acl_name = acl_name
        self.is_global = is_global
        self.interface_ips = interface_ips
        super().__init__(Elements.ENGRESS_INTERFACE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        id = get_xml_int_value(xml_node, Elements.ID)
        direction = get_xml_text_value(xml_node, Elements.DIRECTION)
        device_id = get_xml_text_value(xml_node, Elements.DEVICE_ID)
        acl_name = get_xml_text_value(xml_node, Elements.ACL_NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        interface_ips_node = get_xml_node(xml_node, Elements.INTERFACE_IPS, True)
        if interface_ips_node:
            interface_ips = XML_List.from_xml_node_by_tags(xml_node, Elements.INTERFACE_IPS, Elements.INTERFACE_IP,
                                                           NatInterfaceIP)
        else:
            interface_ips = None

        return cls(name, id, direction, device_id, acl_name, is_global, interface_ips)


class NatInterfaceIP(XML_Object_Base):
    def __init__(self, ip, netmask):
        self.ip = ip
        self.netmask = netmask
        super().__init__(Elements.INTERFACE_IP)

    @classmethod
    def from_xml_node(cls, xml_node):
        ip = get_xml_text_value(xml_node, Elements.IP)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        return cls(ip, netmask)