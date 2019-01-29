import logging
import netaddr

from pytos.common.base_types import XML_Object_Base, XML_List, XSI_Object, Single_Service_Type, Range_Service_Type, \
    Group_Service_Type, Any_Service_Type, Comparable, IPNetworkMixin, Flat_XML_Object_Base
from pytos.common.definitions import xml_tags
from pytos.common.definitions.xml_tags import Attributes
from pytos.common.functions import str_to_bool, get_iana_protocols, netmask_to_cidr, XML_LOGGER_NAME
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value, get_xml_node, \
    create_tagless_xml_objects_list
from pytos.securetrack.xml_objects.base_types import Base_Object, Network_Object, Service
from pytos.securetrack.xml_objects.rest.device import Device, Device_Revision

logger = logging.getLogger(XML_LOGGER_NAME)


class Bindings_List(XML_List):
    def __init__(self, bindings):
        """
        :type bindings: list[Rule_Binding]
        """
        self.bindings = bindings
        super().__init__(xml_tags.Elements.BINDINGS, bindings)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        bindings = []
        for binding_node in xml_node.iter(tag=xml_tags.Elements.BINDING):
            bindings.append(Rule_Binding.from_xml_node(binding_node))
        return cls(bindings)


class Cleanup_Set(XML_Object_Base):
    def __init__(self, shadowed_rules_cleanup=None):
        self.shadowed_rules_cleanup = shadowed_rules_cleanup
        super().__init__(xml_tags.Elements.CLEANUP_SET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules_cleanup = Shadowed_Rules_Cleanup.from_xml_node(
                get_xml_node(xml_node, xml_tags.Elements.SHADOWED_RULES_CLEANUP))
        return cls(shadowed_rules_cleanup)


class Rules_List(XML_List):
    def __init__(self, count, total, rules):
        super().__init__(xml_tags.Elements.RULES, rules)
        self.count = count
        self.total = total

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        count = get_xml_int_value(xml_node, xml_tags.Elements.COUNT)
        total = get_xml_int_value(xml_node, xml_tags.Elements.TOTAL)
        rules = []
        for rule_node in xml_node.iter(tag=xml_tags.Elements.RULE):
            rules.append(Rule.from_xml_node(rule_node))
        return cls(count, total, rules)


class Policy_List(XML_List):
    def __init__(self, policies):
        """
        :type policies: list[Policy]
        """
        super().__init__(xml_tags.Elements.POLICIES, policies)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        policies = []
        for policy_node in xml_node.iter(tag=xml_tags.Elements.POLICY):
            policies.append(Policy.from_xml_node(policy_node))
        return cls(policies)


class Shadowed_Rules_Cleanup(XML_Object_Base):
    def __init__(self, shadowed_rules=None):
        self.shadowed_rules = XML_List(xml_tags.Elements.SHADOWED_RULES, shadowed_rules)
        super().__init__(xml_tags.Elements.SHADOWED_RULES_CLEANUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules = XML_List(xml_tags.Elements.SHADOWED_RULES)
        for shadowed_rule_node in xml_node.iter(tag=xml_tags.Elements.SHADOWED_RULE):
            shadowed_rules.append(Shadowed_Rule.from_xml_node(shadowed_rule_node))
        return cls(shadowed_rules)


class Shadowed_Rule(XML_Object_Base):
    def __init__(self, rule, shadowing_rules=None):
        self.rule = rule
        self.shadowing_rules = shadowing_rules
        super().__init__(xml_tags.Elements.SHADOWED_RULE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        rule = Rule.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.RULE))
        shadowing_rules = []

        shadowing_rules_node = get_xml_node(xml_node, xml_tags.Elements.SHADOWING_RULES, True)
        if shadowing_rules_node:
            for rule_node in shadowing_rules_node.iter(tag=xml_tags.Elements.RULE):
                shadowing_rules.append(Rule.from_xml_node(rule_node))
        else:
            shadowing_rules = None
        return cls(rule, shadowing_rules)


class Record_Set(XML_Object_Base):
    TIME_DATE_FORMAT_STRING = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self, businessowneremail, businessownername, expiredate, record_id, ticketcr, automatic=None):
        self.businessOwnerEmail = businessowneremail
        self.businessOwnerName = businessownername
        self.expireDate = expiredate
        self.id = record_id
        self.ticketCr = ticketcr
        self.automatic = automatic
        super().__init__(xml_tags.Elements.RECORD_SET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        businessowneremail = get_xml_text_value(xml_node, xml_tags.Elements.BUSINESSOWNEREMAIL)
        businessownername = get_xml_text_value(xml_node, xml_tags.Elements.BUSINESSOWNERNAME)
        expiredate = get_xml_text_value(xml_node, xml_tags.Elements.EXPIREDATE)
        record_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        ticketcr = get_xml_text_value(xml_node, xml_tags.Elements.TICKETCR)
        automatic = get_xml_text_value(xml_node, xml_tags.Elements.AUTOMATIC)
        return cls(businessowneremail, businessownername, expiredate, record_id, ticketcr, automatic)

    def set_date_as_expiry_date(self, date):
        new_expiry_date = date.strftime(Record_Set.TIME_DATE_FORMAT_STRING)
        self.expireDate = new_expiry_date

    def is_automatic(self):
        return self.automatic and str_to_bool(self.automatic)


class Rule_Documentation(XML_Object_Base):
    def __init__(self, tech_owner, comment, record_sets, secure_app_applications, new_rule=False, legacy_rule=None,
                 permissiveness_level=None, last_hit=None):
        self.tech_owner = tech_owner
        self.comment = comment
        self.record_sets = record_sets
        self.secure_app_applications = secure_app_applications
        self.legacy_rule = legacy_rule
        self.last_hit = last_hit
        self.permissiveness_level = permissiveness_level
        if new_rule:
            super().__init__(xml_tags.Elements.RULE_DOCUMENTATION)
        else:
            super().__init__(xml_tags.Elements.DOCUMENTATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        tech_owner = get_xml_text_value(xml_node, xml_tags.Elements.TECH_OWNER)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        legacy_rule = get_xml_text_value(xml_node, xml_tags.Elements.LEGACY_RULE)
        permissiveness_level = get_xml_text_value(xml_node, xml_tags.Elements.PERMISSIVENESS_LEVEL)
        last_hit = get_xml_text_value(xml_node, xml_tags.Elements.LAST_HIT)
        record_sets = []
        for record_set_node in xml_node.iter(tag=xml_tags.Elements.RECORD_SET):
            record_sets.append(Record_Set.from_xml_node(record_set_node))
        secure_app_applications = []
        for secure_app_application_node in xml_node.iter(tag=xml_tags.Elements.SECURE_APP_APPLICATION):
            secure_app_applications.append(SecureApp_Application.from_xml_node(secure_app_application_node))

        return cls(tech_owner, comment, record_sets, secure_app_applications, False, legacy_rule, permissiveness_level, last_hit)

    def remove_automatic_record_sets(self):
        if self.record_sets:
            self.record_sets = list(filter(lambda record_set:
                                           not record_set.is_automatic(), self.record_sets))


class Application(XML_Object_Base):
    def __init__(self, app_id, display_name, name):
        self.id = app_id
        self.display_name = display_name
        self.name = name
        super().__init__(xml_tags.Elements.APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
         Initialize the object from a XML node.
         :param xml_node: The XML node from which all necessary parameters will be parsed.
         :type xml_node: xml.etree.Element
         """
        app_id = get_xml_text_value(xml_node, xml_tags.Elements.ID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        return cls(app_id, display_name, name)

    def __str__(self):
        return self.display_name


class Rule(XML_Object_Base, Comparable):
    def __init__(self, num_id, uid, cp_uid, order, binding, action, comment, dst_networks, dst_networks_negated,
                 dst_services, dst_services_negated, disabled, external, name, rule_number, src_networks,
                 src_networks_negated, src_services_negated, track, rule_type, documentation, device_id, implicit,
                 application, vpn, install=None, src_zones=None, dst_zones=None, rule_type_type=None, **kwargs):
        self.id = num_id
        self.uid = uid
        self.cp_uid = cp_uid
        self.order = order
        self.binding = binding
        self.action = action
        self.comment = comment
        self.dst_networks = dst_networks
        self.dst_networks_negated = dst_networks_negated
        self.dst_services = dst_services
        self.dst_services_negated = dst_services_negated
        self.disabled = disabled
        self.external = external
        self.name = name
        self.rule_number = rule_number
        self.src_networks = src_networks
        self.src_networks_negated = src_networks_negated
        self.src_services_negated = src_services_negated
        self.track = track
        self.type = rule_type
        self.documentation = documentation
        self.device_id = device_id
        self.implicit = implicit
        self._network_id_to_object = {}
        self.application = application  # Deprecated, replaced by applications
        self.vpn = vpn
        self.install = install
        self.src_zones = src_zones
        self.dst_zones = dst_zones
        self.rule_type = rule_type_type
        self.additional_parameters = kwargs['additional_parameters']
        self.applications = kwargs['applications']
        self.rule_text = kwargs['rule_text']
        super().__init__(xml_tags.Elements.RULE)

    def _key(self):
        hash_keys = [self.id, self.uid]
        if self.device_id:
            hash_keys.append(self.device_id)
        if self.binding:
            try:
                hash_keys.append(self.binding.uid)
            except AttributeError:
                pass
        return tuple(hash_keys)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        cp_uid = get_xml_text_value(xml_node, xml_tags.Elements.CP_UID)
        order = get_xml_text_value(xml_node, xml_tags.Elements.ORDER)

        binding_node = get_xml_node(xml_node, xml_tags.Elements.BINDING, True)
        binding = Rule_Binding.from_xml_node(binding_node) if binding_node else None

        action = get_xml_text_value(xml_node, xml_tags.Elements.ACTION)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        dst_networks_negated = get_xml_text_value(xml_node, xml_tags.Elements.DEST_NETWORKS_NEGATED)
        dst_services = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.DST_SERVICE, Destination_Service)
        dst_services_negated = get_xml_text_value(xml_node, xml_tags.Elements.DEST_SERVICES_NEGATED)
        disabled = get_xml_text_value(xml_node, xml_tags.Elements.DISABLED)
        external = get_xml_text_value(xml_node, xml_tags.Elements.EXTERNAL)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        rule_number = get_xml_text_value(xml_node, xml_tags.Elements.RULE_NUMBER)
        src_networks = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.SRC_NETWORK, Source_Network)
        dst_networks = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.DST_NETWORK, Destination_Network)
        src_networks_negated = get_xml_text_value(xml_node, xml_tags.Elements.SRC_NETWORKS_NEGATED)
        src_services_negated = get_xml_text_value(xml_node, xml_tags.Elements.SRC_SERVICES_NEGATED)

        track_node = get_xml_node(xml_node, xml_tags.Elements.TRACK, True)
        track = Rule_Track.from_xml_node(track_node) if track_node is not None else None

        rule_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        rule_type_type = get_xml_text_value(xml_node, xml_tags.Elements.RULE_TYPE, True)

        documentation_node = get_xml_node(xml_node, xml_tags.Elements.DOCUMENTATION, True)
        documentation = Rule_Documentation.from_xml_node(documentation_node) if documentation_node else None

        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        vpn = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.VPN, RuleVPNOption)

        rule_text = get_xml_text_value(xml_node, xml_tags.Elements.RULE_TEXT)

        install_node = get_xml_node(xml_node, xml_tags.Elements.INSTALL, True)
        install = Install.from_xml_node(install_node) if install_node else None

        src_zones = [Flat_XML_Object_Base(xml_tags.Elements.SRC_ZONE, content=s_zone.text) for s_zone in xml_node.iter(tag=xml_tags.Elements.SRC_ZONE)]
        dst_zones = [Flat_XML_Object_Base(xml_tags.Elements.DST_ZONE, content=d_zone.text) for d_zone in xml_node.iter(tag=xml_tags.Elements.DST_ZONE)]
        additional_parameters = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.ADDITIONAL_PARAMETER, AdditionalParameter)
        applications = create_tagless_xml_objects_list(xml_node, xml_tags.Elements.APPLICATION, Application)
        application = None

        return cls(num_id, uid, cp_uid, order, binding, action, comment, dst_networks, dst_networks_negated,
                   dst_services, dst_services_negated, disabled, external, name, rule_number, src_networks,
                   src_networks_negated, src_services_negated, track, rule_type, documentation, device_id, implicit,
                   application, vpn, install, src_zones, dst_zones, rule_type_type, rule_text=rule_text,
                   additional_parameters=additional_parameters, applications=applications)

    def __str__(self):
        src_negated, dst_negated, srv_negated = "", "", ""
        if self.src_networks_negated and str_to_bool(self.src_networks_negated):
            src_negated = "NOT "
        if self.dst_networks_negated and str_to_bool(self.dst_networks_negated):
            dst_negated = "NOT "
        if self.dst_services_negated and str_to_bool(self.dst_services_negated):
            srv_negated = "NOT "
        if self.comment:
            comment_str = "COMMENT {}".format(self.comment)
        else:
            comment_str = ""
        return "ACTION {action} FROM {neg_src}{src} TO {neg_dst}{dst} SERVICE {neg_srv}{srv} {comment}".format(
                action=self.action, neg_src=src_negated, src=[str(src) for src in self.src_networks],
                neg_dst=dst_negated, dst=[str(dst) for dst in self.dst_networks], neg_srv=srv_negated,
                srv=[str(srv) for srv in self.dst_services], comment=comment_str)

    @property
    def tuple_header(self):
        if self.src_networks and self.dst_networks:
            return "Rule Number", "Source Negated", "Source", "Destination Negated", "Destination", "Services " \
                                                                                                    "Negated", \
                   "Services", "Action"
        else:
            return "VPN", "Applications"

    def as_tuple(self):
        if self.src_networks and self.dst_networks:
            rule_content = (
                self.rule_number, self.src_networks_negated, ",".join([str(src) for src in self.src_networks]),
                self.dst_networks_negated, ",".join([str(dst) for dst in self.dst_networks]), self.dst_services_negated,
                ",".join([str(srv) for srv in self.dst_services]))
        else:
            rule_content = self.vpn, ', '.join(self.applications)
        return self.tuple_header, rule_content

    def is_enabled(self):
        return not str_to_bool(self.disabled)


class Rule_Binding(XML_Object_Base):
    def __init__(self, acl, policy, default, rule_count, from_zone, to_zone, security_rule_count=None, uid=None,
                 direction=None, display_name=None, sub_policy_name=None):
        self.acl = acl
        self.policy = policy
        self.default = default
        self.rule_count = rule_count
        self.from_zone = from_zone
        self.to_zone = to_zone
        self.security_rule_count = security_rule_count
        self.uid = uid
        self.direction = direction
        self.display_name = display_name
        self.sub_policy_name = sub_policy_name
        super().__init__(xml_tags.Elements.BINDING)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        acl_node = get_xml_node(xml_node, xml_tags.Elements.ACL, True)
        policy_node = get_xml_node(xml_node, xml_tags.Elements.POLICY, True)
        if acl_node is not None:
            acl = Access_List.from_xml_node(acl_node)
        else:
            acl = None
        if policy_node is not None:
            policy = Policy.from_xml_node(policy_node)
        else:
            policy = None
        default = get_xml_text_value(xml_node, xml_tags.Elements.DEFAULT)
        from_zone_node = get_xml_node(xml_node, xml_tags.Elements.FROM_ZONE, True)
        if from_zone_node:
            from_zone = Rule_Binding_Zone.from_xml_node(from_zone_node)
        else:
            from_zone = None
        to_zone_node = get_xml_node(xml_node, xml_tags.Elements.TO_ZONE, True)
        if to_zone_node:
            to_zone = Rule_Binding_Zone.from_xml_node(to_zone_node)
        else:
            to_zone = None
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        rule_count = get_xml_text_value(xml_node, xml_tags.Elements.RULE_COUNT)
        security_rule_count = get_xml_text_value(xml_node, xml_tags.Elements.SECURITY_RULE_COUNT)
        direction = get_xml_text_value(xml_node, xml_tags.Elements.DIRECTION)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        sub_policy_name = get_xml_text_value(xml_node, xml_tags.Elements.SUB_POLICY_NAME)
        return cls(acl, policy, default, rule_count, from_zone, to_zone, security_rule_count, uid, direction,
                   display_name, sub_policy_name)


class Destination_Network(Base_Object):
    def __init__(self, name, display_name, object_id=None, uid=None, implicit=None):
        super().__init__(xml_tags.Elements.DST_NETWORK, name, display_name, object_id, uid, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        return cls(name, display_name, object_id, uid, implicit)


class Source_Network(Base_Object):
    def __init__(self, name, display_name, object_id=None, uid=None, implicit=None):
        super().__init__(xml_tags.Elements.SRC_NETWORK, name, display_name, object_id, uid, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        return cls(name, display_name, object_id, uid, implicit)


class Destination_Service(Base_Object):
    def __init__(self, name, display_name, object_id=None, uid=None, implicit=None):
        super().__init__(xml_tags.Elements.DST_SERVICE, name, display_name, object_id, uid, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        return cls(name, display_name, object_id, uid, implicit)


class RuleVPNOption(Base_Object):
    def __init__(self, name, display_name, object_id=None):
        super().__init__(xml_tags.Elements.VPN, name, display_name, object_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        return cls(name, display_name, object_id)


class Rule_Track(XML_Object_Base):
    NONE = "NONE"
    LOG = "LOG"

    def __init__(self, interval, level=None):
        self.level = level
        self.interval = interval
        super().__init__(xml_tags.Elements.TRACK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        level = get_xml_text_value(xml_node, xml_tags.Elements.LEVEL)
        interval = get_xml_text_value(xml_node, xml_tags.Elements.INTERVAL)
        return cls(interval, level)

    def is_enabled(self):
        if self.level != Rule_Track.NONE:
            return True
        return False

    def is_logged(self):
        if self.level == Rule_Track.LOG:
            return True
        return False


class Access_List(XML_Object_Base):
    def __init__(self, is_global, interfaces=None, name=None):
        self.global_ = is_global
        self.interfaces = interfaces
        self.name = name
        super().__init__(xml_tags.Elements.ACL)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        global_ = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        interfaces = Interface.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.INTERFACES))
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        return cls(global_, interfaces, name)


class Policy(XML_Object_Base):
    def __init__(self, num_id, itg_id, itg, name, unique_active_in_itg=None):
        self.id = num_id
        self.itg = itg
        self.itg_id = itg_id
        self.name = name
        self.unique_active_in_itg = unique_active_in_itg
        super().__init__(xml_tags.Elements.POLICY)

    @classmethod
    def from_xml_node(cls, xml_node=None):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        itg = get_xml_text_value(xml_node, xml_tags.Elements.ITG)
        itg_id = get_xml_int_value(xml_node, xml_tags.Elements.ITG_ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        unique_active_in_itg = get_xml_text_value(xml_node, xml_tags.Elements.UNIQUE_ACTIVE_IN_ITG)
        return cls(num_id, itg_id, itg, name, unique_active_in_itg)

    def __repr__(self):
        return "Policy({id},{itg},{itg_id},'{name}',{unique_active_in_itg})".format(**self.__dict__)


class Interface_IP(XML_Object_Base, IPNetworkMixin):
    def __init__(self, ip, netmask=None, precedence=None, visibility=None):
        self.ip = ip
        self.netmask = netmask
        self.precedence = precedence
        self.visibility = visibility
        super().__init__(xml_tags.Elements.INTERFACE_IP)

    def _get_ip_network(self):
        """

        :rtype: netaddr.IPNetwork
        """
        return netaddr.IPNetwork(self.ip + "/" + self.netmask)

    def __str__(self):
        return "{}/{}".format(self.ip, netmask_to_cidr(self.netmask))

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        netmask = get_xml_text_value(xml_node, xml_tags.Elements.NETMASK)
        precedence = get_xml_text_value(xml_node, xml_tags.Elements.PRECEDENCE)
        visibility = get_xml_text_value(xml_node, xml_tags.Elements.VISIBILITY)
        return cls(ip, netmask, precedence, visibility)


class Interface(XSI_Object):
    def __init__(self, name, num_id, direction, device_id, acl_name, is_global, interface_ips=None):

        self.name = name
        self.id = num_id
        self.direction = direction
        self.device_id = device_id
        self.acl_name = acl_name
        self.interface_ips = interface_ips
        self.global_ = is_global
        super().__init__(xml_tags.Elements.INTERFACE, Attributes.INTERFACE_TYPE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        direction = get_xml_text_value(xml_node, xml_tags.Elements.DIRECTION)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        acl_name = get_xml_text_value(xml_node, xml_tags.Elements.ACL_NAME)
        global_ = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        interface_ips = XML_List(xml_tags.Elements.INTERFACE_IPS)
        for interface_ip_node in xml_node.iter(tag=xml_tags.Elements.INTERFACE_IP):
            interface_ips.append(Interface_IP.from_xml_node(interface_ip_node))
        return cls(name, num_id, direction, device_id, acl_name, global_, interface_ips)


class Topology_Interface(XML_Object_Base):
    def __init__(self, device_id, ip, mask, name, virtual_router, zone):
        self.device_id = device_id
        self.ip = ip
        self.mask = mask
        self.name = name
        self.virtual_router = virtual_router
        self.zone = zone
        super().__init__(xml_tags.Elements.INTERFACE)

    @classmethod
    def from_xml_node(cls, xml_node):
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        mask = get_xml_text_value(xml_node, xml_tags.Elements.MASK)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        virtual_router = get_xml_text_value(xml_node, xml_tags.Elements.VIRTUAL_ROUTER)
        zone = get_xml_text_value(xml_node, xml_tags.Elements.ZONE)
        return cls(device_id, ip, mask, name, virtual_router, zone)


class Services_List(XML_List):
    def __init__(self, services):
        """
        :type services: list[Single_Service]
        """
        self.services = services
        super().__init__(xml_tags.Elements.SERVICES, services)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        services = []
        for service_node in xml_node.iter(tag=xml_tags.Elements.SERVICE):
            if service_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE] == xml_tags.Attributes.SERVICE_TYPE_SINGLE:
                services.append(Single_Service.from_xml_node(service_node))
            elif service_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE] == xml_tags.Attributes.SERVICE_TYPE_GROUP:
                services.append(Group_Service.from_xml_node(service_node))
            else:
                raise ValueError("Unknown service type '{0}'.".format(
                        service_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE]))
        return cls(services)


class Single_Service(Service):
    def __init__(self, service_id, display_name, is_global, name, service_type, protocol, port_min, port_max, negate,
                 comment, uid=None, class_name=None, implicit=None, timeout=None):
        self.protocol = protocol
        self.min = port_min
        self.max = port_max
        self.negate = negate
        self.comment = comment
        self.class_name = class_name
        self.timeout = timeout
        super().__init__(xml_tags.Elements.SERVICE, service_id, display_name, is_global, name, service_type,
                         xml_tags.Attributes.SERVICE_TYPE_SINGLE, uid, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        protocol = get_xml_int_value(xml_node, xml_tags.Elements.PROTOCOL)
        negate = get_xml_text_value(xml_node, xml_tags.Elements.NEGATE)
        port_min = get_xml_int_value(xml_node, xml_tags.Elements.MIN)
        port_max = get_xml_int_value(xml_node, xml_tags.Elements.MAX)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        service_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        service_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        class_name = get_xml_text_value(xml_node, xml_tags.Elements.CLASS_NAME)
        timeout = get_xml_text_value(xml_node, xml_tags.Elements.TIMEOUT)
        return cls(service_id, display_name, is_global, name, service_type, protocol, port_min, port_max, negate,
                   comment, uid, class_name, implicit, timeout)

    def __str__(self):
        iana_protocols = get_iana_protocols()
        if self.min == self.max:
            return "{} {}".format(iana_protocols[int(self.protocol)], self.min)
        else:
            return "{} {}-{}".format(iana_protocols[int(self.protocol)], self.min, self.max)

    def as_service_type(self):
        if self.protocol is not None:
            if self.min == self.max:
                return Single_Service_Type(self.protocol, self.min)
            else:
                return Range_Service_Type(self.protocol, self.min, self.max)
        else:
            return Any_Service_Type()


class Group_Service(Service):
    def __init__(self, service_id, display_name, is_global, name, service_type, members, uid=None, implicit=None):
        self.members = members
        super().__init__(xml_tags.Elements.SERVICE, service_id, display_name, is_global, name, service_type,
                         xml_tags.Attributes.SERVICE_TYPE_GROUP, uid, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        service_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        service_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        members = XML_List(xml_tags.Elements.MEMBERS, [])
        for member_node in xml_node.iter(tag=xml_tags.Elements.MEMBER):
            member_id = get_xml_int_value(member_node, xml_tags.Elements.ID)
            member_display_name = get_xml_text_value(member_node, xml_tags.Elements.DISPLAY_NAME)
            member_name = get_xml_text_value(member_node, xml_tags.Elements.NAME)
            members.append(Base_Object(xml_tags.Elements.MEMBER, member_name, member_display_name, member_id))
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        return cls(service_id, display_name, is_global, name, service_type, members, uid, implicit)

    def __str__(self):
        spacer = 4 * " "
        if self.members:
            return "{}Members:\n{}{}".format(spacer, 2 * spacer, "\n{}".format(2 * spacer).join(
                    [member.display_name for member in self.members]))
        else:
            return "{}No members".format(spacer)

    def as_service_type(self):
        return Group_Service_Type(self.members)


class Network_Objects_List(XML_List):
    def __init__(self, network_objects):
        """
        :type network_objects: list[T <= Network_Object]
        """
        super().__init__(xml_tags.Elements.NETWORK_OBJECTS, network_objects)
        self.network_objects = network_objects

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        network_objects = []
        for network_object_node in xml_node.iter(tag=xml_tags.Elements.NETWORK_OBJECT):
            network_object_type = network_object_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE]

            if network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_BASIC:
                network_objects.append(Basic_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_RANGE:
                network_objects.append(Range_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_HOST:
                network_objects.append(Host_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_HOST_WITH_INTERFACES:
                network_objects.append(Host_With_Interfaces_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_SUBNET:
                network_objects.append(Subnet_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_GROUP:
                network_objects.append(Group_Network_Object.from_xml_node(network_object_node))
            elif network_object_type == xml_tags.Attributes.NETWORK_OBJECT_TYPE_CLOUD:
                network_objects.append(Cloud_Network_Object.from_xml_node(network_object_node))
            else:
                message = "Got unknown type '{}'".format(network_object_type)
                logger.error(message)
                raise ValueError(message)
        return cls(network_objects)


class Basic_Network_Object(Network_Object):
    def __init__(self, display_name, is_global, object_id, name, object_type, ip, device_id, comment, implicit,
                 class_name=None, uid=None):

        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_BASIC)
        self.ip = ip
        self.global_ = is_global
        self.uid = uid
        super().__init__(xml_tags.Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         device_id, comment, implicit, class_name)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        class_name = get_xml_text_value(xml_node, xml_tags.Elements.CLASS_NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        return cls(display_name, is_global, object_id, name, object_type, ip, device_id, comment, implicit, class_name,
                   uid)

    def __str__(self):
        if self.ip is not None:
            return str(self.ip)
        else:
            return "Any"

    def as_netaddr_obj(self):
        if self.ip is not None:
            return netaddr.IPNetwork(self.ip)
        else:
            return netaddr.IPNetwork("0.0.0.0/0")


class Range_Network_Object(Network_Object):
    def __init__(self, display_name, is_global, object_id, name, object_type, first_ip, last_ip, device_id, comment,
                 implicit, uid=None):
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_RANGE)
        self.first_ip = first_ip
        self.last_ip = last_ip
        self.uid = uid
        super().__init__(xml_tags.Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         device_id, comment, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        first_ip = get_xml_text_value(xml_node, xml_tags.Elements.FIRST_IP)
        last_ip = get_xml_text_value(xml_node, xml_tags.Elements.LAST_IP)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        return cls(display_name, is_global, object_id, name, object_type, first_ip, last_ip, device_id, comment,
                   implicit, uid)

    def __str__(self):
        return "{}-{}".format(self.first_ip, self.last_ip)

    def as_netaddr_obj(self):
        return netaddr.IPRange(self.first_ip, self.last_ip, flags=netaddr.ZEROFILL)


class Host_Network_Object(Network_Object):
    def __init__(self, display_name, is_global, object_id, name, object_type, ip, device_id, comment, implicit,
                 uid=None, class_name=None, management_domain=None, nat_info=None):
        super().__init__(xml_tags.Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         device_id, comment, implicit)
        self.ip = ip
        self.uid = uid
        self.class_name = class_name
        self.management_domain = management_domain
        self.nat_info = nat_info
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_HOST)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        class_name = get_xml_text_value(xml_node, xml_tags.Elements.CLASS_NAME)
        management_domain = get_xml_text_value(xml_node, xml_tags.Elements.MANAGEMENT_DOMAIN)

        nat_info = None
        nat_info_node = get_xml_node(xml_node, xml_tags.Elements.NAT_INFO, optional=True)
        if nat_info_node is not None:
            nat_info_type = nat_info_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE]
            if nat_info_type == xml_tags.Attributes.FORTIGATE_NAT_INFO:
                nat_info = FortigateNatInfo.from_xml_node(nat_info_node)

        return cls(display_name, is_global, object_id, name, object_type, ip, device_id, comment, implicit, uid,
                   class_name=class_name, management_domain=management_domain, nat_info=nat_info)

    def __str__(self):
        return self.ip

    def as_netaddr_obj(self):
        return netaddr.IPNetwork(self.ip)


class FortigateNatInfo(XML_Object_Base):
    def __init__(self, **kwargs):
        super().__init__(xml_tags.Elements.NAT_INFO)
        self.id = kwargs['id']
        self.interface_name = kwargs['interface_name']
        self.forti_vip = kwargs['forti_vip']
        self.mapped_ip = kwargs['mapped_ip']
        self.mapped_ip_max = kwargs['mapped_ip_max']
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.FORTIGATE_NAT_INFO)

    @classmethod
    def from_xml_node(cls, xml_node):
        id = get_xml_text_value(xml_node, xml_tags.Elements.ID)
        interface_name = get_xml_text_value(xml_node, xml_tags.Elements.INTERFACE_NAME)
        forti_vip = get_xml_text_value(xml_node, xml_tags.Elements.FORTI_VIP)
        mapped_ip = get_xml_text_value(xml_node, xml_tags.Elements.MAPPED_IP)
        mapped_ip_max = get_xml_text_value(xml_node, xml_tags.Elements.MAPPED_IP_MAX)
        return cls(id=id, interface_name=interface_name, forti_vip=forti_vip, mapped_ip=mapped_ip, mapped_ip_max=mapped_ip_max)


class Host_With_Interfaces_Network_Object(Host_Network_Object):
    def __init__(self, display_name, is_global, object_id, name, object_type, ip, class_name, interfaces, device_id,
                 comment, implicit, uid=None):
        super().__init__(display_name, is_global, object_id, name, object_type, ip, device_id, comment, implicit)
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_HOST_WITH_INTERFACES)
        self.class_name = class_name
        self.interfaces = interfaces
        self.uid = uid

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        class_name = get_xml_text_value(xml_node, xml_tags.Elements.CLASS_NAME)
        interfaces = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.INTERFACES, xml_tags.Elements.INTERFACE,
                                                    Host_Interface, optional=True)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        return cls(display_name, is_global, object_id, name, object_type, ip, class_name, interfaces, device_id,
                   comment, implicit, uid)

    def __str__(self):
        return self.ip


class Host_Interface(XML_Object_Base):
    def __init__(self, ip=None, mask=None, name=None, interface_ips=None):
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_HOST)
        self.name = name
        if interface_ips:
            self.interface_ips = interface_ips
        else:
            self.ip = ip
            self.mask = mask
        super().__init__(xml_tags.Elements.INTERFACE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        try:
            interface_ips = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.INTERFACE_IPS,
                                                           xml_tags.Elements.INTERFACE_IP, Interface_IP)
            return cls(name=name, interface_ips=interface_ips)
        except ValueError:
            ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
            mask = get_xml_text_value(xml_node, xml_tags.Elements.MASK)

            return cls(ip=ip, mask=mask, name=name)


class Subnet_Network_Object(Network_Object):
    def __init__(self, display_name, is_global, object_id, name, object_type, ip, netmask, device_id, comment,
                 implicit, uid=None):
        self.netmask = netmask
        self.ip = ip
        self.uid = uid
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_SUBNET)
        super().__init__(xml_tags.Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         device_id, comment, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        netmask = get_xml_text_value(xml_node, xml_tags.Elements.NETMASK)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        return cls(display_name, is_global, object_id, name, object_type, ip, netmask, device_id, comment, implicit, uid)

    def __str__(self):
        return "{}/{}".format(self.ip, self.netmask)

    def as_netaddr_obj(self):
        return netaddr.IPNetwork("{}/{}".format(self.ip, self.netmask))


class Base_Network_Object(Network_Object):
    def __init__(self, display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                 implicit):
        self.members = members
        self.uid = uid
        super().__init__(xml_tags.Elements.NETWORK_OBJECT, display_name, is_global, connection_id, name, service_type,
                         device_id, comment, implicit)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        connection_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        service_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        members = XML_List(xml_tags.Elements.MEMBERS, [])
        for member_node in xml_node.iter(tag=xml_tags.Elements.MEMBER):
            member_id = get_xml_int_value(member_node, xml_tags.Elements.ID)
            member_display_name = get_xml_text_value(member_node, xml_tags.Elements.DISPLAY_NAME)
            member_name = get_xml_text_value(member_node, xml_tags.Elements.NAME)
            member_uid = get_xml_text_value(member_node, xml_tags.Elements.UID)
            members.append(Base_Object(xml_tags.Elements.MEMBER, member_name, member_display_name, member_id, member_uid))
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        comment = get_xml_text_value(xml_node, xml_tags.Elements.COMMENT)
        implicit = get_xml_text_value(xml_node, xml_tags.Elements.IMPLICIT)
        return cls(display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                   implicit)

    def __str__(self):
        spacer = 4 * " "
        if self.members:
            return "{}Members:\n{}{}".format(spacer, 2 * spacer, "\n{}".format(2 * spacer).join(
                    [member.display_name for member in self.members]))
        else:
            return "{}No members".format(spacer)


class Group_Network_Object(Base_Network_Object):
    def __init__(self, display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                 implicit):
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_GROUP)
        super().__init__(display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                         implicit)


class Cloud_Network_Object(Base_Network_Object):
    def __init__(self, display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                 implicit):
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xml_tags.Attributes.NETWORK_OBJECT_TYPE_CLOUD)
        super().__init__(display_name, is_global, connection_id, name, service_type, members, uid, device_id, comment,
                         implicit)


class Policy_Analysis_Query_Result(XML_Object_Base):
    def __init__(self, devices_and_bindings):
        self.devices_and_bindings = devices_and_bindings
        super().__init__(xml_tags.Elements.POLICY_ANALYSIS_QUERY_RESULT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        devices_and_bindings_node = get_xml_node(xml_node, xml_tags.Elements.DEVICES_AND_BINDINGS)
        devices_and_bindings = Devices_And_Bindings_List.from_xml_node(devices_and_bindings_node)
        return cls(devices_and_bindings)


class Devices_And_Bindings_List(XML_List):
    def __init__(self, items):
        """
        :type items: list[Device_And_Bindings]
        """
        self.items = items
        super().__init__(xml_tags.Elements.DEVICES_AND_BINDINGS, items)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        items = []
        for device_and_bindings_node in xml_node:
            items.append(Device_And_Bindings.from_xml_node(device_and_bindings_node))
        return cls(items)


class Bindings_And_Rules_List(XML_List):
    def __init__(self, items):
        """
        :type items: list[Binding_And_Rules]
        """
        self.items = items
        super().__init__(xml_tags.Elements.BINDINGS_AND_RULES, items)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        items = []
        for device_and_bindings_node in xml_node:
            items.append(Binding_And_Rules.from_xml_node(device_and_bindings_node))
        return cls(items)


class Binding_And_Rules(XML_Object_Base):
    def __init__(self, bindings, rules):
        self.bindings = bindings
        self.rules = rules
        super().__init__(xml_tags.Elements.BINDING_AND_RULES)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        rules = []
        rules_node = get_xml_node(xml_node, xml_tags.Elements.RULES)
        for rule_node in rules_node.iter(tag=xml_tags.Elements.RULE):
            rules.append(Rule.from_xml_node(rule_node))
        binding_node = get_xml_node(xml_node, xml_tags.Elements.BINDING)
        binding = Rule_Binding.from_xml_node(binding_node)
        return cls(binding, rules)


class Device_And_Bindings(XML_Object_Base):
    def __init__(self, device, bindings_and_rules):
        self.device = device
        self.bindings_and_rules = bindings_and_rules
        super().__init__(xml_tags.Elements.DEVICE_AND_BINDINGS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        device_node = get_xml_node(xml_node, xml_tags.Elements.DEVICE)
        device = Device.from_xml_node(device_node)
        bindings_and_rules_node = get_xml_node(xml_node, xml_tags.Elements.BINDINGS_AND_RULES)
        bindings_and_rules = Bindings_And_Rules_List.from_xml_node(bindings_and_rules_node)
        return cls(device, bindings_and_rules)


class SecureApp_Application(XML_Object_Base):
    def __init__(self, app_name, app_owner):
        """
        Initialize the object from parameters.
        :param app_name: The name of the application.
        :type app_name: str
        :param app_owner: The application owner.
        :type app_owner: str
        """
        self.app_name = app_name
        self.app_owner = app_owner
        super().__init__(xml_tags.Elements.SECURE_APP_APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        app_owner = get_xml_text_value(xml_node, xml_tags.Elements.APP_OWNER)
        app_name = get_xml_text_value(xml_node, xml_tags.Elements.APP_NAME)
        return cls(app_name, app_owner)


class Interfaces_List(XML_List):
    def __init__(self, interfaces):
        """
        :type interfaces: list[Interface]
        """
        super().__init__(xml_tags.Elements.INTERFACES, interfaces)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interfaces = []
        for interface_node in xml_node.iter(tag=xml_tags.Elements.INTERFACE):
            interfaces.append(Interface.from_xml_node(interface_node))
        return cls(interfaces)


class Topology_Interfaces_List(XML_List):
    def __init__(self, interfaces):
        """
        :type interfaces: list[Topology_Interface]
        """
        super().__init__(xml_tags.Elements.INTERFACES, interfaces)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interfaces = []
        for interface_node in xml_node.iter(tag=xml_tags.Elements.INTERFACE):
            interfaces.append(Topology_Interface.from_xml_node(interface_node))
        return cls(interfaces)


class Change_Rules(XML_Object_Base):
    def __init__(self, xml_tag, new_rule, old_rules, old_rules_violated_traffic):
        """
        :type xml_tag: str
        :type new_rule: Rule
        :type old_rules: XML_List
        :type old_rules_violated_traffic: OldRulesViolatedTraffic
        """
        super().__init__(xml_tag)
        self.new_rule = new_rule
        self.old_rules = old_rules
        self.old_rules_violated_traffic = old_rules_violated_traffic

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        # TODO: Rule has an incorrect tag of "rule", should be "new_rule" here.
        new_rule = Rule.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.NEW_RULE))
        new_rule._xml_tag = xml_tags.Elements.NEW_RULE
        old_rules = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.OLD_RULES, xml_tags.Elements.OLD_RULE,
                                                   Rule)
        old_rules_violated_traffic_node = get_xml_node(xml_node, xml_tags.Elements.OLD_RULES_VIOLATED_TRAFFIC, True)
        if old_rules_violated_traffic_node is not None:
            old_rules_violated_traffic = OldRulesViolatedTraffic.from_xml_node(old_rules_violated_traffic_node)
        else:
            old_rules_violated_traffic = None
        return cls(xml_tags.Elements.ACCEPTINGRULESDTO, new_rule, old_rules, old_rules_violated_traffic)


class OldRulesViolatedTraffic(XML_Object_Base):
    def __init__(self, rule_violated_traffic):
        super().__init__(xml_tags.Elements.OLD_RULES_VIOLATED_TRAFFIC)
        self.rule_violated_traffic = rule_violated_traffic

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        rule_violated_traffic_node = get_xml_node(xml_node, xml_tags.Elements.RULE_VIOLATED_TRAFFIC)
        rule_violated_traffic = RuleViolatedTraffic.from_xml_node(rule_violated_traffic_node)
        return cls(rule_violated_traffic)


class RuleViolatedTraffic(XML_Object_Base):
    def __init__(self, violated_traffic):
        super().__init__(xml_tags.Elements.RULE_VIOLATED_TRAFFIC)
        self.violated_traffic = violated_traffic

    @classmethod
    def from_xml_node(cls, xml_node):
        violated_traffic = ViolatedTraffic.from_xml_node(xml_node)
        return cls(violated_traffic)


class ViolatedTraffic(XML_List):
    def __init__(self, traffic_ranges):
        super().__init__(xml_tags.Elements.VIOLATED_TRAFFIC, traffic_ranges)

    @classmethod
    def from_xml_node(cls, xml_node):
        traffic_ranges = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.VIOLATED_TRAFFIC,
                                                        xml_tags.Elements.TRAFFIC_RANGE, TrafficRange)
        return cls(traffic_ranges)


class Change_Accepting_Rules(Change_Rules):
    def __init__(self, new_rule, old_rules, old_rules_violated_traffic):
        super().__init__(xml_tags.Elements.ACCEPTINGRULESDTO, new_rule, old_rules, old_rules_violated_traffic)


class Change_Blocking_Rules(Change_Rules):
    def __init__(self, new_rule, old_rules, old_rules_violated_traffic):
        super().__init__(xml_tags.Elements.BLOCKINGRULESDTO, new_rule, old_rules, old_rules_violated_traffic)


class Change_Authorization(XML_Object_Base):
    UNAUTHORIZED = "unauthorized"
    AUTHORIZED = "authorized"

    def __init__(self, status, new_revision, old_revision, change_auth_bindings):
        """
        :type status: str
        :type new_revision: Device_Revision
        :type old_revision: Device_Revision
        :type change_auth_bindings: ChangeAuthorizationBindings
        """
        super().__init__(xml_tags.Elements.CHANGE_AUTHORIZATION)
        self.status = status
        self.new_revision = new_revision
        self.old_revision = old_revision
        self.change_authorization_bindings = change_auth_bindings

    @classmethod
    def from_xml_node(cls, xml_node=None):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        status = get_xml_text_value(xml_node, xml_tags.Elements.STATUS)
        new_revision_node = get_xml_node(xml_node, xml_tags.Elements.NEW_REVISION)
        new_revision = Device_Revision.from_xml_node(new_revision_node)
        old_revision_node = get_xml_node(xml_node, xml_tags.Elements.OLD_REVISION)
        old_revision = Device_Revision.from_xml_node(old_revision_node)
        change_auth_bindings_node = get_xml_node(xml_node, xml_tags.Elements.CHANGE_AUTHORIZATION_BINDINGS)
        change_auth_bindings = ChangeAuthorizationBindings.from_xml_node(change_auth_bindings_node)
        return cls(status, new_revision, old_revision, change_auth_bindings)

    def is_authorized(self):
        return self.status.lower() == self.AUTHORIZED.lower()


class PolicyZonePair(XML_Object_Base):
    def __init__(self, src_zone, dst_zone):
        super().__init__(xml_tags.Elements.POLICY_ZONE_PAIR)
        self.src_zone = src_zone
        self.dst_zone = dst_zone

    @classmethod
    def from_xml_node(cls, xml_node):
        src_zone = get_xml_text_value(xml_node, xml_tags.Elements.SRC_ZONE)
        dst_zone = get_xml_text_value(xml_node, xml_tags.Elements.DST_ZONE)
        return cls(src_zone, dst_zone)


class ChangeAuthorizationBinding(XML_Object_Base):
    def __init__(self, binding, unauthorized_opened_access, unauthorized_closed_access, policy_zone_pair):
        """
        :type binding: Rule_Binding
        :type unauthorized_opened_access: XML_List[Change_Accepting_Rules]
        :type unauthorized_closed_access: XML_List[Change_Blocking_Rules]
        """
        super().__init__(xml_tags.Elements.CHANGE_AUTHORIZATION_BINDING)
        self.binding = binding
        self.policy_zone_pair = policy_zone_pair
        self.unauthorized_opened_access = unauthorized_opened_access
        self.unauthorized_closed_access = unauthorized_closed_access

    @classmethod
    def from_xml_node(cls, xml_node):
        unauthorized_opened_access = XML_List.from_xml_node_by_tags(xml_node,
                                                                    xml_tags.Elements.UNAUTHORIZED_OPENED_ACCESS,
                                                                    xml_tags.Elements.ACCEPTINGRULESDTO,
                                                                    Change_Accepting_Rules)

        unauthorized_closed_access = XML_List.from_xml_node_by_tags(xml_node,
                                                                    xml_tags.Elements.UNAUTHORIZED_CLOSED_ACCESS,
                                                                    xml_tags.Elements.BLOCKINGRULESDTO,
                                                                    Change_Blocking_Rules)
        binding_node = get_xml_node(xml_node, xml_tags.Elements.BINDING, True)
        if binding_node:
            binding = Rule_Binding.from_xml_node(binding_node)
        else:
            binding = None
        policy_zone_pair_node = get_xml_node(xml_node, xml_tags.Elements.POLICY_ZONE_PAIR, True)
        if policy_zone_pair_node:
            policy_zone_pair = PolicyZonePair.from_xml_node(policy_zone_pair_node)
        else:
            policy_zone_pair = None
        return cls(binding, unauthorized_opened_access, unauthorized_closed_access, policy_zone_pair)


class ChangeAuthorizationBindings(XML_List):
    def __init__(self, change_auth_bindings):
        """
        :type change_auth_bindings: list[ChangeAuthorizationBinding]
        """
        super().__init__(xml_tags.Elements.CHANGE_AUTHORIZATION_BINDINGS, change_auth_bindings)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        change_auth_bindings = []
        for change_auth_binding_node in xml_node.iter(tag=xml_tags.Elements.CHANGE_AUTHORIZATION_BINDING):
            change_auth_bindings.append(ChangeAuthorizationBinding.from_xml_node(change_auth_binding_node))
        return cls(change_auth_bindings)


class Rule_Binding_Zone(XML_Object_Base):
    def __init__(self, xml_tag, name, is_global, zone_id):
        super().__init__(xml_tag)
        self.id = zone_id
        self.global_ = is_global
        self.name = name

    @classmethod
    def from_xml_node(cls, xml_node):
        zone_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        is_global = get_xml_text_value(xml_node, xml_tags.Elements.GLOBAL)
        return cls(xml_node.tag, name, is_global, zone_id)


class SecurityRequirement(XML_Object_Base):
    def __init__(self, policy_control_name, access_type, from_zone, to_zone, rule_properties, flow, allowed_services,
                 blocked_services):
        super().__init__(xml_tags.Elements.SECURITY_REQUIREMENT)
        self.policy_control_name = policy_control_name
        self.access_type = access_type
        self.from_zone = from_zone
        self.to_zone = to_zone
        self.rule_properties = rule_properties
        self.flow = flow
        self.allowed_services = allowed_services
        self.blocked_services = blocked_services

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        policy_control_name = get_xml_text_value(xml_node, xml_tags.Elements.POLICY_CONTROL_NAME)
        access_type = get_xml_text_value(xml_node, xml_tags.Elements.ACCESS_TYPE)
        from_zone = get_xml_text_value(xml_node, xml_tags.Elements.FROM_ZONE)
        to_zone = get_xml_text_value(xml_node, xml_tags.Elements.TO_ZONE)

        rule_properties_node = get_xml_node(xml_node, xml_tags.Elements.RULE_PROPERTIES, optional=True)
        if rule_properties_node is None:
            rule_properties = None
        else:
            rule_properties = RuleProperties.from_xml_node(rule_properties_node)

        flow_node = get_xml_node(xml_node, xml_tags.Elements.FLOW, optional=True)
        if flow_node is None:
            flow = None
        else:
            flow = Flow.from_xml_node(flow_node)

        allowed_services_node = get_xml_node(xml_node, xml_tags.Elements.ALLOWED_SERVICES, optional=True)
        if allowed_services_node is None:
            allowed_services = None
        else:
            allowed_services = AllowedServices.from_xml_node(allowed_services_node)

        blocked_services_node = get_xml_node(xml_node, xml_tags.Elements.BLOCKED_SERVICES, optional=True)
        if blocked_services_node is None:
            blocked_services = None
        else:
            blocked_services = BlockedServices.from_xml_node(blocked_services_node)

        return cls(policy_control_name, access_type, from_zone, to_zone, rule_properties, flow, allowed_services,
                   blocked_services)


class AllowedOrBlockedServicesBase(XML_Object_Base):
    """
    Base class for either the "allowed services" or "blocked services" nodes of the "security_requirement" node
    (violations XML)
    """

    def __init__(self, id_, exclude_any, is_any, negate, service_items, xml_tag):
        super().__init__(xml_tag)
        self.id = id_
        self.exclude_any = exclude_any
        self.is_any = is_any
        self.negate = negate
        self.service_items = service_items


class AllowedServices(AllowedOrBlockedServicesBase):
    """
    Parses the "allowed services" node of the "security_requirement" node in the violations XML
    """

    def __init__(self, id_, exclude_any, is_any, negate, service_items):
        super().__init__(id_, exclude_any, is_any, negate, service_items, xml_tags.Elements.ALLOWED_SERVICES)

    @classmethod
    def from_xml_node(cls, xml_node):
        allowed_services_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        exclude_any = get_xml_text_value(xml_node, xml_tags.Elements.EXCLUDE_ANY)
        is_any = get_xml_text_value(xml_node, xml_tags.Elements.IS_ANY)
        negate = get_xml_text_value(xml_node, xml_tags.Elements.NEGATE)
        service_items = ServiceItemsList.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.SERVICE_ITEMS))
        return cls(allowed_services_id, exclude_any, is_any, negate, service_items)


class BlockedServices(AllowedOrBlockedServicesBase):
    """
    Parses the "blocked services" node of the "security_requirement" node in the violations XML
    """

    def __init__(self, id_, exclude_any, is_any, negate, service_items):
        super().__init__(id_, exclude_any, is_any, negate, service_items, xml_tags.Elements.BLOCKED_SERVICES)

    @classmethod
    def from_xml_node(cls, xml_node):
        blocked_services_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        exclude_any = get_xml_text_value(xml_node, xml_tags.Elements.EXCLUDE_ANY)
        is_any = get_xml_text_value(xml_node, xml_tags.Elements.IS_ANY)
        negate = get_xml_text_value(xml_node, xml_tags.Elements.NEGATE)
        service_items = ServiceItemsList.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.SERVICE_ITEMS))
        return cls(blocked_services_id, exclude_any, is_any, negate, service_items)


class ServiceItem(XML_Object_Base):
    def __init__(self, id_, port, protocol):
        super().__init__(xml_tags.Elements.SERVICE_ITEM)
        self.id = id_
        self.port = port
        self.protocol = protocol

    @classmethod
    def from_xml_node(cls, xml_node):
        service_item_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        port = get_xml_text_value(xml_node, xml_tags.Elements.PORT)
        protocol = get_xml_text_value(xml_node, xml_tags.Elements.PROTOCOL)
        return cls(service_item_id, port, protocol)


class ServiceItemsList(XML_List):
    def __init__(self, service_items):
        self.service_items = service_items
        super().__init__(xml_tags.Elements.SERVICE_ITEMS, service_items)

    @classmethod
    def from_xml_node(cls, xml_node):
        services_items = []
        for service_item in xml_node.iter(tag=xml_tags.Elements.SERVICE_ITEM):
            service_item_obj = ServiceItem.from_xml_node(service_item)
            if service_item_obj is not None:
                services_items.append(service_item_obj)
        return cls(services_items)


class Flow(XML_Object_Base):
    """
    Parses the "flow" node of the "security_requirement" node. Represents the configured flow in the USP matrix.
    """

    def __init__(self, description, property_type):
        super().__init__(xml_tags.Elements.FLOW)
        self.description = description
        self.type = property_type

    @classmethod
    def from_xml_node(cls, xml_node):
        description = get_xml_text_value(xml_node, xml_tags.Elements.DESCRIPTION)
        property_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        return cls(description, property_type)


class RuleProperty(XML_Object_Base):
    """
    Parses a "rule property" node of the "security_requirement" node.
    """

    def __init__(self, description, property_type, payload):
        super().__init__(xml_tags.Elements.RULE_PROPERTY)
        self.description = description
        self.type = property_type
        self.payload = payload

    @classmethod
    def from_xml_node(cls, xml_node):
        description = get_xml_text_value(xml_node, xml_tags.Elements.DESCRIPTION)
        property_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        payload = get_xml_text_value(xml_node, xml_tags.Elements.PAYLOAD)
        return cls(description, property_type, payload)


class RuleProperties(XML_List):
    def __init__(self, rule_properties_list):
        self.rule_properties_list = rule_properties_list
        super().__init__(xml_tags.Elements.RULE_PROPERTY, rule_properties_list)

    @classmethod
    def from_xml_node(cls, xml_node):
        rule_properties_list = []
        for rule_property in xml_node.iter(tag=xml_tags.Elements.RULE_PROPERTY):
            rule_property_obj = RuleProperty.from_xml_node(rule_property)
            if rule_property_obj is not None:
                rule_properties_list.append(rule_property_obj)
        return cls(rule_properties_list)


class RulePropertyViolation(XML_Object_Base):
    def __init__(self, description, property_type):
        super().__init__(xml_tags.Elements.RULE_PROPERTY_VIOLATION)
        self.description = description
        self.type = property_type

    @classmethod
    def from_xml_node(cls, xml_node):
        description = get_xml_text_value(xml_node, xml_tags.Elements.DESCRIPTION)
        property_type = get_xml_text_value(xml_node, xml_tags.Elements.TYPE)
        return cls(description, property_type)


class RulePropertyViolations(XML_List):
    def __init__(self, rule_properties_violations_list):
        self.rule_properties_violations_list = rule_properties_violations_list
        super().__init__(xml_tags.Elements.RULE_PROPERTY_VIOLATION, rule_properties_violations_list)

    @classmethod
    def from_xml_node(cls, xml_node):
        rule_properties_violations_list = []
        for rule_property_violation in xml_node.iter(tag=xml_tags.Elements.RULE_PROPERTY_VIOLATION):
            rule_property_violation_obj = RulePropertyViolation.from_xml_node(rule_property_violation)
            if rule_property_violation_obj is not None:
                rule_properties_violations_list.append(rule_property_violation_obj)
        return cls(rule_properties_violations_list)


class ViolatingObject(XML_Object_Base):
    def __init__(self, path):
        super().__init__(xml_tags.Elements.VIOLATING_OBJECT)
        self.path = path

    @classmethod
    def from_xml_node(cls, xml_node):
        path = get_xml_text_value(xml_node, xml_tags.Elements.PATH)
        return cls(path)


class FlowViolationsBase(XML_Object_Base):
    """
    Base class for the the "flow source violations" and "flow destination violations" nodes of the
    "violation" node.
    """

    def __init__(self, xml_tag, negated, violating_objects):
        super().__init__(xml_tag)
        self.negated = negated
        self.violating_object = violating_objects

    @classmethod
    def get_negated_and_violating_rules(cls, xml_node):
        negated = get_xml_text_value(xml_node, xml_tags.Elements.NEGATED)
        violating_objects = []
        for violating_object_node in xml_node.iter(tag=xml_tags.Elements.VIOLATING_OBJECT):
            violating_object = ViolatingObject.from_xml_node(violating_object_node)
            if violating_object is not None:
                violating_objects.append(violating_object)
        return negated, violating_objects


class FlowSourceViolations(FlowViolationsBase):
    def __init__(self, negated, violating_objects):
        super().__init__(xml_tags.Elements.FLOW_SOURCE_VIOLATIONS, negated, violating_objects)

    @classmethod
    def from_xml_node(cls, xml_node):
        negated, violating_objects = super().get_negated_and_violating_rules(xml_node)
        return cls(negated, violating_objects)


class FlowDestinationViolations(FlowViolationsBase):
    def __init__(self, negated, violating_objects):
        super().__init__(xml_tags.Elements.FLOW_DESTINATION_VIOLATIONS, negated, violating_objects)

    @classmethod
    def from_xml_node(cls, xml_node):
        negated, violating_objects = super().get_negated_and_violating_rules(xml_node)
        return cls(negated, violating_objects)


class Path(Flat_XML_Object_Base):
    def __init__(self, path):
        super().__init__(xml_tag=xml_tags.Elements.PATH, content=path)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls(get_xml_text_value(xml_node, xml_tags.Elements.PATH))


class ViolationNetwork(XML_Object_Base):
    def __init__(self, paths):
        super().__init__(xml_tags.Elements.NETWORK)
        self.paths = paths

    @classmethod
    def from_xml_node(cls, xml_node):
        paths = []
        for path in xml_node.iter(tag=xml_tags.Elements.NETWORK):
            paths.append(Path.from_xml_node(path))
        return cls(paths)

    def get_all_paths_as_string(self):
        return '-'.join(path.content for path in self.paths)


class SourcesInZone(XML_Object_Base):
    def __init__(self, zone_name, networks):
        super().__init__(xml_tags.Elements.SOURCES_IN_ZONE)
        self.zone_name = zone_name
        self.networks = networks

    @classmethod
    def from_xml_node(cls, xml_node):
        sources_in_zone_node = get_xml_node(xml_node, xml_tags.Elements.SOURCES_IN_ZONE, optional=True)
        if sources_in_zone_node is None:
            return None
        zone_name = get_xml_text_value(sources_in_zone_node, xml_tags.Elements.ZONE_NAME)
        networks = XML_List.from_xml_node_by_tags(sources_in_zone_node, xml_tags.Elements.NETWORKS,
                                                  xml_tags.Elements.NETWORK, ViolationNetwork)
        return cls(zone_name, networks)


class DestinationsInZone(XML_Object_Base):
    def __init__(self, zone_name, networks):
        super().__init__(xml_tags.Elements.DESTINATIONS_IN_ZONE)
        self.zone_name = zone_name
        self.networks = networks

    @classmethod
    def from_xml_node(cls, xml_node):
        destinations_in_zone_node = get_xml_node(xml_node, xml_tags.Elements.DESTINATIONS_IN_ZONE, optional=True)
        if destinations_in_zone_node is None:
            return None
        zone_name = get_xml_text_value(destinations_in_zone_node, xml_tags.Elements.ZONE_NAME)
        networks = XML_List.from_xml_node_by_tags(destinations_in_zone_node, xml_tags.Elements.NETWORKS,
                                                  xml_tags.Elements.NETWORK, ViolationNetwork)
        return cls(zone_name, networks)


class ViolatingService(XML_Object_Base):
    def __init__(self, paths):
        self.paths = paths
        super().__init__(xml_tags.Elements.VIOLATING_SERVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        paths = []
        for path in xml_node.iter(tag=xml_tags.Elements.VIOLATING_SERVICE):
            paths.append(Path.from_xml_node(path))
        return cls(paths)

    def get_all_paths_as_string(self):
        return '-'.join(path.content for path in self.paths)


class ViolatingServices(XML_Object_Base):
    def __init__(self, negated, services):
        self.negated = negated
        self.services = services
        super().__init__(xml_tags.Elements.VIOLATING_SERVICES)

    @classmethod
    def from_xml_node(cls, xml_node):
        violating_services_node = get_xml_node(xml_node, xml_tags.Elements.VIOLATING_SERVICES)
        if violating_services_node is None:
            return None
        negated = get_xml_text_value(violating_services_node, xml_tags.Elements.NEGATED)
        services_list = []
        for violating_service in violating_services_node.iter(tag=xml_tags.Elements.VIOLATING_SERVICE):
            services_list.append(ViolatingService.from_xml_node(violating_service))
        return cls(negated, services_list)


class Violation(XML_Object_Base):
    # TODO: expend the Class to Any type of violation
    def __init__(self, severity, security_requirement, rule_properties_violations, flow_source_violations,
                 flow_destination_violations, sources_in_zone=None, destinations_in_zone=None, violating_services=None):
        super().__init__(xml_tags.Elements.VIOLATION)
        self.security_requirement = security_requirement
        self.severity = severity
        self.rule_properties_violations = rule_properties_violations
        self.flow_source_violations = flow_source_violations
        self.flow_destination_violations = flow_destination_violations
        self.sources_in_zone = sources_in_zone
        self.destinations_in_zone = destinations_in_zone
        self.violating_services = violating_services

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        severity = get_xml_text_value(xml_node, xml_tags.Elements.SEVERITY)
        # TODO: currently it parses only single type of requirement, should be done for all types and done by dict
        try:
            xpath = '{}[@{}="{}"]'.format(xml_tags.Elements.SECURITY_REQUIREMENT,
                                          xml_tags.Attributes.XSI_NAMESPACE_TYPE,
                                          xml_tags.Attributes.SECURITY_REQUIREMENT_TYPE_MATRIX)
            security_requirement_node = xml_node.findall(xpath)[0]
        except (ValueError, IndexError):
            return None
        else:
            security_requirement = SecurityRequirement.from_xml_node(security_requirement_node)

            rule_properties_violations_node = get_xml_node(xml_node, xml_tags.Elements.RULE_PROPERTIES_VIOLATIONS,
                                                           optional=True)
            if rule_properties_violations_node is None:
                rule_properties_violations = None
            else:
                rule_properties_violations = RulePropertyViolations.from_xml_node(rule_properties_violations_node)

            flow_source_violations_node = get_xml_node(xml_node, xml_tags.Elements.FLOW_SOURCE_VIOLATIONS,
                                                       optional=True)
            if flow_source_violations_node is None:
                flow_source_violations = None
            else:
                flow_source_violations = FlowSourceViolations.from_xml_node(flow_source_violations_node)

            flow_destination_violations_node = get_xml_node(xml_node, xml_tags.Elements.FLOW_SOURCE_VIOLATIONS,
                                                            optional=True)
            if flow_destination_violations_node is None:
                flow_destination_violations = None
            else:
                flow_destination_violations = FlowDestinationViolations.from_xml_node(flow_destination_violations_node)

            sources_in_zone = SourcesInZone.from_xml_node(xml_node)
            destinations_in_zone = DestinationsInZone.from_xml_node(xml_node)
            violating_services = ViolatingServices.from_xml_node(xml_node)

            return cls(severity, security_requirement, rule_properties_violations, flow_source_violations,
                       flow_destination_violations, sources_in_zone, destinations_in_zone, violating_services)


class ViolatingRule(XML_Object_Base):
    def __init__(self, rule, violations):
        super().__init__(xml_tags.Elements.VIOLATING_RULE)
        self.rule = rule
        self.violations = violations

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        rule = Rule.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.RULE))
        violations = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.VIOLATIONS, xml_tags.Elements.VIOLATION,
                                                    Violation)
        return cls(rule, violations)


class SecurityPolicyDeviceViolations(XML_Object_Base):
    def __init__(self, device_name, severity, violating_rules):
        super().__init__(xml_tags.Elements.SECURITY_POLICY_DEVICE_VIOLATIONS)
        self.device_name = device_name
        self.severity = severity
        self.violating_rules = violating_rules

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        device_name = get_xml_text_value(xml_node, xml_tags.Elements.DEVICE_NAME)
        severity = get_xml_text_value(xml_node, xml_tags.Elements.SEVERITY)
        violating_rules = XML_List.from_xml_node_by_tags(xml_node, xml_tags.Elements.VIOLATING_RULES,
                                                         xml_tags.Elements.VIOLATING_RULE, ViolatingRule)
        return cls(device_name, severity, violating_rules)


class TrafficRangeObject(XML_Object_Base):
    def __init__(self, tag, from_, to):
        """
        :type tag: str
        :type from_: str
        :type to: str
        """
        super().__init__(tag)
        self.from_ = from_
        self.to = to

    def __str__(self):
        if self.from_ == self.to:
            return str(self.from_)
        else:
            return "{}-{}".format(self.from_, self.to)

    def __repr__(self):
        return "{}({},{})".format(self.__class__.__name__, self.from_, self.to)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        from_ = get_xml_text_value(xml_node, xml_tags.Elements.FROM)
        to = get_xml_text_value(xml_node, xml_tags.Elements.TO)
        return cls(xml_tags.Elements.SRC, from_, to)


class TrafficRangeSrc(TrafficRangeObject):
    def __init__(self, from_, to):
        super().__init__(xml_tags.Elements.SRC, from_, to)


class TrafficRangeDst(TrafficRangeObject):
    def __init__(self, from_, to):
        super().__init__(xml_tags.Elements.DST, from_, to)


class TrafficRangeProtocol(TrafficRangeObject):
    def __init__(self, from_, to):
        super().__init__(xml_tags.Elements.PROTOCOL, from_, to)


class TrafficRangePort(TrafficRangeObject):
    def __init__(self, from_, to):
        super().__init__(xml_tags.Elements.PORT, from_, to)


class TrafficRange(XML_Object_Base):
    def __init__(self, src, dst, protocol, port):
        """
        :type src: TrafficRangeSrc
        :type dst: TrafficRangeDst
        :type protocol: TrafficRangeProtocol
        :type port: TrafficRangePort
        """
        super().__init__(xml_tags.Elements.TRAFFIC_RANGE)
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.port = port

    def __repr__(self):
        return "TrafficRange('{}','{}','{}','{}')".format(self.src, self.dst, self.protocol, self.port)

    @property
    def tuple_header(self):
        return "Source", "Destination", "Protocol", "Port"

    def as_tuple(self):
        content = self.src, self.dst, self.protocol, self.port
        return self.tuple_header, content

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        src = TrafficRangeSrc.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.SRC))
        dst = TrafficRangeDst.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.DST))
        protocol = TrafficRangeProtocol.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.PROTOCOL))
        port = TrafficRangePort.from_xml_node(get_xml_node(xml_node, xml_tags.Elements.PORT))
        return cls(src, dst, protocol, port)

    def as_netaddr_obj(self):
        if self.src.from_ == self.src.to:
            src = netaddr.IPNetwork(self.src.from_, flags=netaddr.ZEROFILL)
        else:
            src = netaddr.IPRange(self.src.from_, self.src.to, flags=netaddr.ZEROFILL)
        return src

    def as_netaddr_set(self):
        """This returns a netaddr set representing the TrafficRange"""
        return netaddr.IPSet(self.as_netaddr_obj())

    def as_service_type(self):
        if self.port.from_ == self.port.to:
            return Single_Service_Type(self.protocol.from_, self.port.from_)
        else:
            return Range_Service_Type(self.protocol.from_, self.port.from_, self.port.to)


class Install(XML_Object_Base):
    def __init__(self, id_, uid, display_name, name):
        self.id = id_
        self.uid = uid
        self.display_name = display_name
        self.name = name
        super().__init__(xml_tags.Elements.INSTALL)

    @classmethod
    def from_xml_node(cls, xml_node):
        id_ = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        return cls(id_, uid, display_name, name)


class AdditionalParameter(Base_Object):
    def __init__(self, name, display_name, uid):
        super().__init__(xml_tags.Elements.ADDITIONAL_PARAMETER, name, display_name, uid)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        display_name = get_xml_text_value(xml_node, xml_tags.Elements.DISPLAY_NAME)
        uid = get_xml_text_value(xml_node, xml_tags.Elements.UID)
        return cls(name, display_name, uid)
