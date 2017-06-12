
import logging
import netaddr

from pytos.secureapp.xml_objects.base_types import Base_Link_Target, Base_Object, URL_Link, Network_Object, Service_Object
from pytos.common.base_types import XML_Object_Base, XML_List, Group_Service_Type, Single_Service_Type, \
    Range_Service_Type, Any_Service_Type, Comparable
from pytos.common.definitions.xml_tags import Attributes, Elements
from pytos.common.functions import str_to_bool, XML_LOGGER_NAME
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value, get_xml_node

logger = logging.getLogger(XML_LOGGER_NAME)


class Applications_List(XML_List):
    def __init__(self, applications):
        """
        :type: applications: list[Application]
        """
        super().__init__(Elements.APPLICATIONS, applications)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        applications = []
        for application_node in xml_node.iter(tag=Elements.APPLICATION):
            applications.append(Application.from_xml_node(application_node))
        return cls(applications)


class Application(XML_Object_Base, Comparable):
    def __init__(self, app_id, name, comment, decommissioned, owner, editors, created, modified, status, connections,
                 open_tickets, customer=None, connection_to_application_packs=None):
        self.id = app_id
        self.name = name
        self.comment = comment
        self.decommissioned = decommissioned
        self.owner = owner
        self.editors = editors
        self.created = created
        self.modified = modified
        self.status = status
        self.connections = connections
        self.open_tickets = open_tickets
        # customer is used only on >=15.1 but if send on prev version it will be ignored and no error will be generated
        self.customer = customer

        self.connection_to_application_packs = connection_to_application_packs
        super().__init__(Elements.APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        app_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        decommissioned = get_xml_text_value(xml_node, Elements.DECOMMISSIONED)
        owner = Application_Owner.from_xml_node(get_xml_node(xml_node, Elements.OWNER))
        created = get_xml_text_value(xml_node, Elements.CREATED)
        modified = get_xml_text_value(xml_node, Elements.MODIFIED)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        editors = XML_List.from_xml_node_by_tags(xml_node, Elements.EDITORS, Elements.EDITOR, Application_Editor)
        open_tickets = XML_List.from_xml_node_by_tags(xml_node, Elements.OPEN_TICKETS, Elements.TICKET,
                                                      Application_Open_Ticket)
        # For <15.1 compatibility we would not force to get this one as it will fail
        customer_xml_node = get_xml_node(xml_node, Elements.CUSTOMER, True)
        if customer_xml_node is not None:
            customer = Customer.from_xml_node(customer_xml_node)
        else:
            customer = None

        connection_to_application_packs = XML_List.from_xml_node_by_tags(xml_node,
                                                                         Elements.CONNECTION_TO_APPLICATION_PACKS,
                                                                         Elements.CONNECTION_TO_APPLICATION_PACK,
                                                                         Connection_To_Application_Pack, True)

        connections = []
        for connection_node in xml_node.iter(tag=Elements.CONNECTION):
            connections.append(Application_Connection.from_xml_node(connection_node))
        return cls(app_id, name, comment, decommissioned, owner, editors, created, modified, status, connections,
                   open_tickets, customer, connection_to_application_packs)

    def is_decommissioned(self):
        return str_to_bool(self.decommissioned)

    def _key(self):
        return self.id, self.name

    def __repr__(self):
        return 'Application. Name: {}, Owner: {}'.format(self.name, self.owner.display_name)

    def __str__(self):
        return repr(self)


class Application_Reference(Base_Link_Target):
    def __init__(self, app_id, display_name, name, link):
        super().__init__(Elements.APPLICATION, app_id, display_name, name, link)

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


class Application_Open_Ticket(Base_Link_Target):
    def __init__(self, ticket_id, display_name, name, link):
        super().__init__(Elements.TICKET, ticket_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """

        ticket_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(ticket_id, display_name, name, link)


class Application_Editor(Base_Link_Target):
    def __init__(self, editor_id, display_name, name, link):
        super().__init__(Elements.EDITOR, editor_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """

        editor_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(editor_id, display_name, name, link)


class Application_Owner(Base_Link_Target):
    def __init__(self, owner_id, display_name, name, link):
        super().__init__(Elements.OWNER, owner_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """

        owner_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(owner_id, display_name, name, link)


class Server(Base_Link_Target):
    def __init__(self, server_id, display_name, name, server_type, link):
        self.type = server_type
        super().__init__(Elements.SERVER, server_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        server_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        server_type = get_xml_text_value(xml_node, Elements.TYPE)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(server_id, display_name, name, server_type, link)


class Connection_To_Application(Base_Link_Target):
    def __init__(self, conn_to_app_id, display_name, name, link):
        super().__init__(Elements.CONNECTION_TO_APPLICATION, conn_to_app_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        conn_to_app_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(conn_to_app_id, display_name, name, link)


class Connection_To_Application_Pack(Base_Link_Target):
    def __init__(self, conn_to_app_pack_id, display_name, name, link):
        super().__init__(Elements.CONNECTION_TO_APPLICATION_PACK, conn_to_app_pack_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        conn_to_app_pack_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(conn_to_app_pack_id, display_name, name, link)


class Application_Pack(Base_Link_Target):
    def __init__(self, app_pack_id, display_name, name, link):
        super().__init__(Elements.APPLICATION_PACK, app_pack_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        app_pack_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(app_pack_id, display_name, name, link)


class Application_Connection(Base_Link_Target):
    def __init__(self, connection_id, display_name, name, link):
        super().__init__(Elements.CONNECTION, connection_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(connection_id, display_name, name, link)


class Tag_Reference(Base_Link_Target):
    def __init__(self, tag_id, display_name, name, link):
        super().__init__(Elements.TAG, tag_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        tag_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(tag_id, display_name, name, link)


class Tag_Servers(XML_List):
    """
    :type tags: list[Tag_Reference]
    """

    def __init__(self, tags):
        super().__init__(Elements.TAG_SERVERS, tags)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        tags = []
        for connection_node in xml_node.iter(tag=Elements.TAG):
            tags.append(Tag_Reference.from_xml_node(connection_node))
        return cls(tags)


class User_List(XML_List):
    """
    :type users: list[User]
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
        for user_node in xml_node.iter(tag=Elements.USER):
            users.append(User.from_xml_node(user_node))
        return cls(users)


class User(Base_Object):
    def __init__(self, display_name, is_global, user_id, name, user_type, ip):
        self.ip = ip
        super().__init__(Elements.USER, display_name, is_global, user_id, name, user_type)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        user_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        user_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        return cls(display_name, is_global, user_id, name, user_type, ip)

    def _key(self):
        return self.ip,


class Connection_List(XML_List):
    """
    :type connections: list[Detailed_Application_Connection]
    """

    def __init__(self, connections):
        super().__init__(Elements.CONNECTIONS, connections)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connections = []
        for connection_node in xml_node.iter(tag=Elements.CONNECTION):
            connections.append(Detailed_Application_Connection.from_xml_node(connection_node))
        return cls(connections)


class ConnectionExtendedList(XML_List):
    def __init__(self, connections):
        super().__init__(Elements.CONNECTIONS_EXTENDED, connections)

    @classmethod
    def from_xml_node(cls, xml_node):
        connections = []
        for con_node in xml_node.iter(tag=Elements.CONNECTION_EXTENDED):
            connections.append(ConnectionExtended.from_xml_node(con_node))
        return cls(connections)


class Detailed_Connection_To_Application(XML_Object_Base):
    def __init__(self, con_to_app_id, name, comment, application_id, application_interface_id, connections):
        self.id = con_to_app_id
        self.name = name
        self.comment = comment
        self.application_id = application_id
        self.application_interface_id = application_interface_id
        self.connections = connections
        super().__init__(Elements.CONNECTION_TO_APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        con_to_app_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        app_interface_id = get_xml_int_value(xml_node, Elements.APPLICATION_INTERFACE_ID)
        connections = XML_List.from_xml_node_by_tags(xml_node, Elements.CONNECTIONS, Elements.CONNECTION,
                                                     Detailed_Application_Connection, True)
        return cls(con_to_app_id, name, comment, application_id, app_interface_id, connections)


class Detailed_Connection_To_Application_Pack(XML_Object_Base):
    def __init__(self, conn_to_app_pack_id, name, comment, created, modified, application, application_pack,
                 connection_to_applications, tags_servers):
        self.id = conn_to_app_pack_id
        self.name = name
        self.comment = comment
        self.created = created
        self.modified = modified
        self.application = application
        self.application_pack = application_pack
        self.connection_to_applications = connection_to_applications
        self.tags_servers = tags_servers
        super().__init__(Elements.CONNECTION_TO_APPLICATION_PACK)

    @classmethod
    def from_xml_node(cls, xml_node):
        conn_to_app_pack_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        created = get_xml_text_value(xml_node, Elements.CREATED)
        modified = get_xml_text_value(xml_node, Elements.MODIFIED)
        app = None
        app_node = get_xml_node(xml_node, Elements.APPLICATION)
        if app_node:
            app = Application_Reference.from_xml_node(app_node)
        application_pack = None
        app_pack_node = get_xml_node(xml_node, Elements.APPLICATION_PACK)
        if app_pack_node:
            Application_Pack.from_xml_node(app_pack_node)
        connection_to_applications = XML_List.from_xml_node_by_tags(xml_node, Elements.CONNECTION_TO_APPLICATIONS,
                                                                    Elements.CONNECTION_TO_APPLICATION,
                                                                    Connection_To_Application, True)
        tags_servers = XML_List.from_xml_node_by_tags(xml_node, Elements.TAGS_SERVERS, Elements.TAG_SERVERS,
                                                      Tag_Servers, True)
        return cls(conn_to_app_pack_id, name, comment, created, modified, app, application_pack,
                   connection_to_applications, tags_servers)


class Connection_To_Application_Packs(XML_List):
    """
    :type connection_to_application_packs: list[Detailed_Connection_To_Application_Pack]
    """

    def __init__(self, connection_to_application_packs):
        super().__init__(Elements.CONNECTION_TO_APPLICATION_PACKS, connection_to_application_packs)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_to_application_packs = []
        for con_to_app_node in xml_node.iter(tag=Elements.CONNECTION_TO_APPLICATION_PACK):
            connection_to_application_packs.append(
                    Detailed_Connection_To_Application_Pack.from_xml_node(con_to_app_node))
        return cls(connection_to_application_packs)


class Connections_To_Applications(XML_List):
    """
    :type connections_to_applications: list[Detailed_Connection_To_Application]
    """

    def __init__(self, connections_to_applications):
        super().__init__(Elements.CONNECTIONS_TO_APPLICATIONS, connections_to_applications)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connections_to_applications = []
        for con_to_app_node in xml_node.iter(tag=Elements.CONNECTION_TO_APPLICATION):
            connections_to_applications.append(Detailed_Connection_To_Application.from_xml_node(con_to_app_node))
        return cls(connections_to_applications)


class ConnectionExtended(XML_Object_Base):
    def __init__(self, con_id, name, comment, open_tickets, external, status, sources, services, destinations,
                 connection_to_application):
        self.id = con_id
        self.name = name
        self.comment = comment
        self.open_tickets = open_tickets
        self.external = external
        self.status = status
        self.sources = sources
        self.services = services
        self.destinations = destinations
        self.connection_to_application = connection_to_application
        super().__init__(Elements.CONNECTION_EXTENDED)

    @classmethod
    def from_xml_node(cls, xml_node):
        con_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        open_tickets = XML_List.from_xml_node_by_tags(xml_node, Elements.OPEN_TICKETS, Elements.TICKET,
                                                      Application_Open_Ticket, True)
        external = get_xml_text_value(xml_node, Elements.EXTERNAL)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        sources = []
        destinations = []
        services = []
        sources_node = get_xml_node(xml_node, Elements.SOURCES, True)
        if sources_node:
            for src_node in sources_node.iter(tag=Elements.SOURCE):
                sources.append(Network_Object.from_xml_node_auto_type(src_node))
        destinations_node = get_xml_node(xml_node, Elements.DESTINATIONS, True)
        if destinations_node:
            for dst_node in destinations_node.iter(tag=Elements.DESTINATION):
                destinations.append(Network_Object.from_xml_node_auto_type(dst_node))
        services_node = get_xml_node(xml_node, Elements.SERVICES, True)
        if services_node:
            for srv_node in services_node.iter(tag=Elements.SERVICE):
                services.append(Service_Object.from_xml_node_auto_type(srv_node))
        connection_to_application = None
        con_to_app_node = get_xml_node(xml_node, Elements.CONNECTION_TO_APPLICATION, True)
        if con_to_app_node:
            connection_to_application = Detailed_Connection_To_Application.from_xml_node(con_to_app_node)
        return cls(con_id, name, comment, open_tickets, external, status, sources, services, destinations,
                   connection_to_application)


class Detailed_Application_Connection(XML_Object_Base):
    def __init__(self, connection_id, name, external, sources, services, destinations, comment, status, open_tickets,
                 connection_to_application=None):
        self.id = connection_id
        self.name = name
        self.external = external
        self.sources = XML_List(Elements.SOURCES, sources)
        self.services = XML_List(Elements.SERVICES, services)
        self.destinations = XML_List(Elements.DESTINATIONS, destinations)
        self.comment = comment
        self.status = status
        self.open_tickets = open_tickets
        self.connection_to_application = connection_to_application
        super().__init__(Elements.CONNECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        sources = XML_List.from_xml_node_by_tags(xml_node, Elements.SOURCES, Elements.SOURCE, Source, True)
        services = XML_List.from_xml_node_by_tags(xml_node, Elements.SERVICES, Elements.SERVICE, Connection_Service,
                                                  True)
        destinations = XML_List.from_xml_node_by_tags(xml_node, Elements.DESTINATIONS, Elements.DESTINATION,
                                                      Destination, True)
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        external = get_xml_text_value(xml_node, Elements.EXTERNAL)
        name = get_xml_text_value(xml_node, Elements.NAME)
        open_tickets = XML_List.from_xml_node_by_tags(xml_node, Elements.OPEN_TICKETS, Elements.TICKET,
                                                      Application_Open_Ticket, True)
        connection_to_application = None
        connection_to_application_node = get_xml_node(xml_node, Elements.CONNECTION_TO_APPLICATION, True)
        if connection_to_application_node:
            connection_to_application = Connection_To_Application.from_xml_node(connection_to_application_node)
        return cls(connection_id, name, external, sources, services, destinations, comment, status, open_tickets,
                   connection_to_application)

    def __repr__(self):
        srcs_string = ','.join(str(src) for src in self.sources)
        dsts_string = ','.join(str(dst) for dst in self.destinations)
        srvs_string = ','.join(str(srv) for srv in self.services)
        return 'Detailed Application Connection. Name: {}, <Sources: {}>, <Destinations: {}>, <Services: {}>'.format(
                                                                                                     self.name,
                                                                                                     srcs_string,
                                                                                                     dsts_string,
                                                                                                     srvs_string)

    def __str__(self):
        return repr(self)


class Interface_Connection(XML_Object_Base):
    def __init__(self, interface_connection_id, name, sources, services, comment, open_tickets, connected_servers):
        self.id = interface_connection_id
        self.name = name
        self.sources = sources
        self.services = services
        self.comment = comment
        self.open_tickets = open_tickets
        self.connected_servers = connected_servers
        super().__init__(Elements.INTERFACE_CONNECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interface_connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        sources = XML_List.from_xml_node_by_tags(xml_node, Elements.SOURCES, Elements.SOURCE, Source, True)

        services = XML_List.from_xml_node_by_tags(xml_node, Elements.SERVICES, Elements.SERVICE, Connection_Service,
                                                  True)
        connected_servers = XML_List.from_xml_node_by_tags(xml_node, Elements.CONNECTED_SERVERS, Elements.SERVER,
                                                           Server, True)
        open_tickets = XML_List.from_xml_node_by_tags(xml_node, Elements.OPEN_TICKETS, Elements.TICKET,
                                                      Application_Open_Ticket, True)

        return cls(interface_connection_id, name, sources, services, comment, open_tickets, connected_servers)


class Application_Interface(XML_Object_Base):
    def __init__(self, interface_id, name, comment, is_published, application_id, interface_connections):
        self.id = interface_id
        self.name = name
        self.comment = comment
        self.is_published = is_published
        self.application_id = application_id
        self.interface_connections = interface_connections
        super().__init__(Elements.APPLICATION_INTERFACE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interface_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        is_published = get_xml_text_value(xml_node, Elements.IS_PUBLISHED)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        interface_connections = XML_List.from_xml_node_by_tags(xml_node, Elements.INTERFACE_CONNECTIONS,
                                                               Elements.INTERFACE_CONNECTION, Interface_Connection,
                                                               True)

        return cls(interface_id, name, comment, is_published, application_id, interface_connections)


class Application_Interfaces(XML_List):
    """
    :type application_interfaces: list[Application_Interface]
    """

    def __init__(self, application_interfaces):
        super().__init__(Elements.APPLICATION_INTERFACES, application_interfaces)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        app_interfaces = []
        for app_interface_node in xml_node.iter(tag=Elements.APPLICATION_INTERFACE):
            app_interfaces.append(Application_Interface.from_xml_node(app_interface_node))
        return cls(app_interfaces)


class Connection_Service(Base_Link_Target):
    def __init__(self, connection_id, display_name, name, link):
        super().__init__(Elements.SERVICE, connection_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(connection_id, display_name, name, link)


class Services_List(XML_List):
    """
    :type services: list[Single_Service]
    """

    def __init__(self, services):
        super().__init__(Elements.SERVICES, services)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        services = []
        for service_node in xml_node.iter(tag=Elements.SERVICE):
            if service_node.attrib[Attributes.XSI_NAMESPACE_TYPE] == Attributes.SERVICE_TYPE_SINGLE:
                services.append(Single_Service.from_xml_node(service_node))
            elif service_node.attrib[Attributes.XSI_NAMESPACE_TYPE] == Attributes.SERVICE_TYPE_GROUP:
                services.append(Group_Service.from_xml_node(service_node))
            else:
                raise ValueError(
                        "Unknown service type '{}'.".format(service_node.attrib[Attributes.XSI_NAMESPACE_TYPE]))
        return cls(services)


class Single_Service(Service_Object):
    class_identifier = Attributes.SERVICE_TYPE_SINGLE

    def __init__(self, display_name, is_global, connection_id, name, service_type, protocol, port_min, port_max, negate,
                 uid, comment, app_id=None, timeout=None):
        self.protocol = protocol
        self.min = port_min
        self.max = port_max
        self.negate = negate
        self.uid = uid
        self.comment = comment
        self.timeout = 'default' if timeout is None else timeout
        super().__init__(Elements.SERVICE, display_name, is_global, connection_id, name, service_type,
                         Attributes.SERVICE_TYPE_SINGLE, app_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        protocol = get_xml_int_value(xml_node, Elements.PROTOCOL)
        negate = get_xml_text_value(xml_node, Elements.NEGATE)
        port_min = get_xml_int_value(xml_node, Elements.MIN)
        port_max = get_xml_int_value(xml_node, Elements.MAX)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        service_type = get_xml_text_value(xml_node, Elements.TYPE)
        uid = get_xml_text_value(xml_node, Elements.UID)
        app_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        return cls(display_name, is_global, connection_id, name, service_type, protocol, port_min, port_max, negate,
                   uid, comment, app_id, timeout)

    def as_service_type(self):
        if self.protocol is not None:
            if self.min == self.max:
                return Single_Service_Type(self.protocol, self.min)
            else:
                return Range_Service_Type(self.protocol, self.min, self.max)
        else:
            return Any_Service_Type()

    def _key(self):
        return self.protocol, self.min, self.max, self.negate, self.uid, self.comment, self.timeout

    @classmethod
    def from_st_service_object(cls, st_service_object):
        return cls(st_service_object.display_name, st_service_object.global_, None,
                   st_service_object.name, st_service_object.type, st_service_object.protocol, st_service_object.min,
                   st_service_object.max, st_service_object.negate, None, st_service_object.comment)

    def __repr__(self):
        return 'type: {}, {}'.format(self.type, self.display_name)

    def __str__(self):
        return repr(self)


class Group_Service(Service_Object):
    class_identifier = Attributes.SERVICE_TYPE_GROUP

    def __init__(self, display_name, is_global, connection_id, name, service_type, members, uid, application_id=None):
        self.members = members
        self.uid = uid

        super().__init__(Elements.SERVICE, display_name, is_global, connection_id, name, service_type,
                         Attributes.SERVICE_TYPE_GROUP, application_id)

    def as_service_type(self):
        return Group_Service_Type(self.members)

    def _key(self):
        return self.id, self.uid, self.name, self.application_id, self.global_

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        service_type = get_xml_text_value(xml_node, Elements.TYPE)
        uid = get_xml_text_value(xml_node, Elements.UID)
        app_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        members = []
        for member_node in xml_node.iter(tag=Elements.MEMBER):
            member_id = get_xml_int_value(member_node, Elements.ID)
            member_display_name = get_xml_text_value(member_node, Elements.DISPLAY_NAME)
            member_name = get_xml_text_value(member_node, Elements.NAME)
            member_link = URL_Link.from_xml_node(member_node.find(Elements.LINK))
            members.append(Base_Link_Target(Elements.MEMBER, member_id, member_display_name, member_name, member_link))
        return cls(display_name, is_global, connection_id, name, service_type, members, uid, app_id)

    @classmethod
    def from_st_service_object(cls, st_service_object):
        members = []
        for member in st_service_object.members:
            members.append(Base_Link_Target(Elements.MEMBER, None, member.display_name, member.name, None))

        return cls(st_service_object.display_name, st_service_object.global_, None, st_service_object.name,
                   st_service_object.type, members, None)


    def __repr__(self):
        return 'Service Group: {}. members: {}'.format(self.display_name, ', '.join(str(member)
                                                                                    for member in self.members))

    def __str__(self):
        return repr(self)


class Source(Base_Link_Target):
    def __init__(self, connection_id, display_name, name, link, source_type):
        self.type = source_type
        super().__init__(Elements.SOURCE, connection_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        source_type = get_xml_text_value(xml_node, Elements.TYPE)
        return cls(connection_id, display_name, name, link, source_type)

    def __repr__(self):
        return self.display_name

    def __str__(self):
        return repr(self)


class Destination(Base_Link_Target):
    def __init__(self, connection_id, display_name, name, link, destination_type):
        self.type = destination_type
        super().__init__(Elements.DESTINATION, connection_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        dest_type = get_xml_text_value(xml_node, Elements.TYPE)
        return cls(connection_id, display_name, name, link, dest_type)

    def __repr__(self):
        return self.display_name

    def __str__(self):
        return repr(self)


class Network_Objects_List(XML_List):
    """
    :type network_objects: list[Network_Object]
    """

    def __init__(self, network_objects):
        super().__init__(Elements.NETWORK_OBJECTS, network_objects)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        network_objects = []
        for network_object_node in xml_node.iter(tag=Elements.NETWORK_OBJECT):
            network_objects.append(Network_Object.from_xml_node_auto_type(network_object_node))
        return cls(network_objects)


class Basic_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_BASIC

    def __init__(self, display_name, is_global, object_id, name, object_type, ip, application_id=None):

        self.ip = ip
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_BASIC, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, object_id, name, object_type, ip, application_id)

    def as_netaddr_obj(self):
        if self.ip:
            return netaddr.IPNetwork(self.ip)
        else:
            return netaddr.IPNetwork("0.0.0.0/0")

    @classmethod
    def from_st_network_object(cls, st_network_obj):
        return cls(st_network_obj.display_name, st_network_obj.global_, None, st_network_obj.name, st_network_obj.type,
                   st_network_obj.ip, application_id=None)


class Internet_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_INTERNET

    def __init__(self, display_name, is_global, object_id, name, object_type, application_id=None):
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_INTERNET, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, object_id, name, object_type, application_id)


class Range_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_RANGE

    def __init__(self, display_name, is_global, object_id, name, object_type, first_ip, last_ip, application_id=None):
        self.first_ip = first_ip
        self.last_ip = last_ip
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_RANGE, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        first_ip = get_xml_text_value(xml_node, Elements.FIRST_IP)
        last_ip = get_xml_text_value(xml_node, Elements.LAST_IP)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, object_id, name, object_type, first_ip, last_ip, application_id)

    @classmethod
    def from_st_network_object(cls, st_network_obj):
        return cls(st_network_obj.display_name, st_network_obj.global_, None, st_network_obj.name, st_network_obj.type,
                   st_network_obj.first_ip, st_network_obj.last_ip)

    def as_netaddr_obj(self):
        return netaddr.IPRange(self.first_ip, self.last_ip)

    def __repr__(self):
        return 'Range Network Object. Name: {}, First IP: {}, Last IP: {}'.format(self.display_name, self.first_ip,
                                                                                  self.last_ip)

    def __str__(self):
        return repr(self)


class Host_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_HOST

    def __init__(self, display_name, is_global, object_id, name, object_type, ip, application_id=None):
        self.ip = ip
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_HOST, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, object_id, name, object_type, ip, application_id)

    @classmethod
    def from_st_network_object(cls, st_network_obj):
        return cls(st_network_obj.display_name, st_network_obj.global_, None, st_network_obj.name, st_network_obj.type,
                   st_network_obj.ip)

    def as_netaddr_obj(self):
        return netaddr.IPNetwork(self.ip)

    def _key(self):
        return self.ip,

    def __repr__(self):
        return 'Host Network Object. Name: {}, IP: {}'.format(self.display_name, self.ip)

    def __str__(self):
        return repr(self)


class Subnet_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_SUBNET

    def __init__(self, display_name, is_global, object_id, name, object_type, ip, netmask, application_id=None):
        self.netmask = netmask
        self.ip = ip
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_SUBNET, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        ip = get_xml_text_value(xml_node, Elements.IP)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, object_id, name, object_type, ip, netmask, application_id)

    @classmethod
    def from_st_network_object(cls, st_network_obj):
        return cls(st_network_obj.display_name, st_network_obj.global_, None, st_network_obj.name, st_network_obj.type,
                   st_network_obj.ip, st_network_obj.netmask)

    def as_netaddr_obj(self):
        return netaddr.IPNetwork(str(self.ip) + "/" + str(self.netmask))

    def _key(self):
        return self.ip, self.netmask

    def __repr__(self):
        return 'Subnet Network Object. Name: {}, IP: {}, Netmask: {}'.format(self.display_name, self.ip, self.netmask)

    def __str__(self):
        return repr(self)


# TODO: Validate with real device. NOT TESTED!
class Pool_Member(XML_Object_Base):
    def __init__(self, ip, netmask, name):
        self.name = name
        self.ip = ip
        self.netmask = netmask
        super().__init__(Attributes.POOL_MEMBER)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        return cls(ip, netmask, name)


class Virtual_Server_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_VIRTUAL_SERVER

    def __init__(self, display_name, is_global, object_id, name, object_type, netmask, app_id, uid, virtual_ip,
                 protocol, f5_device_name, port, comment, device_id, pool_member):
        self.netmask = netmask
        self.virtual_ip = virtual_ip
        self.netmask = netmask
        self.uid = uid
        self.protocol = protocol
        self.f5_device_name = f5_device_name
        self.port = port
        self.comment = comment
        self.device_id = device_id
        self.pool_member = pool_member
        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                         Attributes.NETWORK_OBJECT_TYPE_VIRTUAL_SERVER, app_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        object_type = get_xml_text_value(xml_node, Elements.TYPE)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        virtual_ip = get_xml_text_value(xml_node, Elements.VIRTUAL_IP)
        app_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        protocol = get_xml_text_value(xml_node, Elements.PROTOCOL)
        f5_device_name = get_xml_text_value(xml_node, Elements.F5_DEVICE_NAME)
        port = get_xml_int_value(xml_node, Elements.PORT)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        pool_member = XML_List.from_xml_node_by_tags(xml_node, Elements.POOL_MEMBERS, Elements.POOL_MEMBER, Pool_Member)

        return cls(display_name, is_global, object_id, name, object_type, netmask, app_id, uid, virtual_ip, protocol,
                   f5_device_name, port, comment, device_id, pool_member)

    def as_netaddr_obj(self):
        return netaddr.IPNetwork(str(self.virtual_ip) + "/" + str(self.netmask))


class VM_Instance(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_VM_INSTANCE

    def __init__(self, object_id, object_type, name, is_global, display_name,
                 instance_id, security_groups, comment, interfaces, device, application_id, ip, availability_zone,
                 vendor, tags, uid, status, host_name, original_instance_id):
        self.ip = ip
        self.instance_id = instance_id
        self.availability_zone = availability_zone
        self.vendor = vendor
        self.tags = tags
        self.uid = uid
        self.security_groups = security_groups
        self.device_info = device
        self.status = status
        self.host_name = host_name
        self.interfaces = interfaces
        self.original_instance_id = original_instance_id
        self.application_id = application_id
        self.comment = comment

        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, object_id, name, object_type,
                        Attributes.NETWORK_OBJECT_TYPE_VM_INSTANCE)

    @classmethod
    def from_xml_node(cls, xml_node):
        object_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        global_ = get_xml_text_value(xml_node, Elements.GLOBAL)
        type_ = get_xml_text_value(xml_node, Elements.TYPE)

        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        instance_id = get_xml_text_value(xml_node, Elements.INSTANCE_ID)
        availability_zone = get_xml_text_value(xml_node, Elements.AVAILABILITY_ZONE)
        vendor = get_xml_text_value(xml_node, Elements.VENDOR)
        tags = Tags.from_xml_node(get_xml_node(xml_node, Elements.TAGS))
        uid = get_xml_text_value(xml_node, Elements.UID)
        security_groups = Security_Groups.from_xml_node(get_xml_node(xml_node, Elements.SECURITY_GROUPS))
        device_info = Device_Info.from_xml_node(get_xml_node(xml_node, Elements.DEVICE_INFO))
        status = get_xml_text_value(xml_node, Elements.STATUS)
        host_name = get_xml_text_value(xml_node, Elements.HOST_NAME)
        interfaces = Interfaces.from_xml_node(get_xml_node(xml_node, Elements.INTERFACES))
        original_instance_id = get_xml_int_value(xml_node, Elements.ORIGINAL_INSTANCE_ID)
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)

        return cls(object_id, type_, name, global_, display_name, instance_id, security_groups, comment,
                   interfaces, device_info, application_id, ip, availability_zone, vendor, tags, uid, status,
                   host_name, original_instance_id)


class Tag(XML_Object_Base):
    def __init__(self, key, value):
        self.key = key
        self.value = value
        super().__init__(Elements.TAG)

    @classmethod
    def from_xml_node(cls, xml_node):
        key = get_xml_text_value(xml_node, Elements.KEY)
        value = get_xml_text_value(xml_node, Elements.VALUE)

        return cls(key, value)


class Tags(XML_List):
    def __init__(self, tags):
        super().__init__(Elements.TAGS, tags)

    @classmethod
    def from_xml_node(cls, xml_node):
        """ Initialize the object from a XML node.

        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        tags = []
        for tag_node in xml_node.iter(tag=Elements.TAG):
            tags.append(Tag.from_xml_node(tag_node))
        return cls(tags)


class VM_Instances(XML_List):
    def __init__(self, vm_instances):
        super().__init__(Elements.VM_INSTANCES, vm_instances)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        vm_instances = []
        for vm_instance_node in xml_node.iter(tag=Elements.VM_INSTANCE):
            vm_instances.append(VM_Instance.from_xml_node(vm_instance_node))
        return cls(vm_instances)


class Interface(XML_Object_Base):
    def __init__(self, name, interface_ips):
        self.name = name
        self.interface_ips = interface_ips

        super().__init__(Elements.INTERFACE)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        interface_ips = Interface_IPs.from_xml_node(get_xml_node(xml_node, Elements.INTERFACE_IPS))

        return cls(name, interface_ips)


class Interfaces(XML_List):
    def __init__(self, interfaces):
        super().__init__(Elements.INTERFACES, interfaces)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interfaces = []
        for interface_node in xml_node.iter(tag=Elements.INTERFACE):
            interfaces.append(Interface.from_xml_node(interface_node))
        return cls(interfaces)


class Interface_IP(XML_Object_Base):
    def __init__(self, ip, primary, visibility):
        self.ip = ip
        self.primary = primary
        self.visibility = visibility

        super().__init__(Elements.INTERFACE_IP)

    @classmethod
    def from_xml_node(cls, xml_node):
        ip = get_xml_text_value(xml_node, Elements.IP)
        primary = get_xml_text_value(xml_node, Elements.PRIMARY)
        visibility = get_xml_text_value(xml_node, Elements.VISIBILITY)

        return cls(ip, primary, visibility)


class Interface_IPs(XML_List):
    def __init__(self, interface_ips):
        super().__init__(Elements.INTERFACE_IPS, interface_ips)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interface_ips = []
        for interface_ip_node in xml_node.iter(tag=Elements.INTERFACE_IP):
            interface_ips.append(Interface_IP.from_xml_node(interface_ip_node))
        return cls(interface_ips)


class Group_Network_Object(Network_Object):
    class_identifier = Attributes.NETWORK_OBJECT_TYPE_GROUP

    def __init__(self, display_name, is_global, connection_id, name, service_type, members, application_id=None):
        self.members = members

        super().__init__(Elements.NETWORK_OBJECT, display_name, is_global, connection_id, name, service_type,
                         Attributes.NETWORK_OBJECT_TYPE_GROUP, application_id)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        is_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        service_type = get_xml_text_value(xml_node, Elements.TYPE)
        members = XML_List(Elements.MEMBERS, [])
        for member_node in xml_node.iter(tag=Elements.MEMBER):
            member_id = get_xml_int_value(member_node, Elements.ID)
            member_display_name = get_xml_text_value(member_node, Elements.DISPLAY_NAME)
            member_name = get_xml_text_value(member_node, Elements.NAME)
            member_link = URL_Link.from_xml_node(member_node.find(Elements.LINK))
            members.append(Base_Link_Target(Elements.MEMBER, member_id, member_display_name, member_name, member_link))
        application_id = get_xml_int_value(xml_node, Elements.APPLICATION_ID)
        return cls(display_name, is_global, connection_id, name, service_type, members, application_id)

    @classmethod
    def from_st_network_object(cls, st_network_obj):
        members = []
        for member in st_network_obj.members:
            members.append(Base_Link_Target(Elements.MEMBER, None, member.display_name, member.name, None))

        sa_group_obj = cls(st_network_obj.display_name, st_network_obj.global_, None, st_network_obj.name,
                           st_network_obj.type, members)

        return sa_group_obj

    def __repr__(self):
        return 'Group Network Object. Name: {},Members: {}'.format(self.display_name,
                                                                   ','.join(str(member) for member in self.members))

    def __str__(self):
        return repr(self)


class Customers_List(XML_List):
    def __init__(self, customers):
        """
        :type customers: list[Detailed_Customer]
        """
        super().__init__(Elements.CUSTOMERS, customers)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        customers = []
        for customer_node in xml_node.iter(tag=Elements.CUSTOMER):
            customers.append(Detailed_Customer.from_xml_node(customer_node))
        return cls(customers)


class Detailed_Customer(XML_Object_Base):
    def __init__(self, customer_id, name, usage_mode, status):
        self.id = customer_id
        self.name = name
        self.usage_mode = usage_mode
        self.status = status
        super().__init__(Elements.CUSTOMER)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        customer_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        usage_mode = get_xml_text_value(xml_node, Elements.USAGE_MODE)
        status = get_xml_text_value(xml_node, Elements.STATUS)
        return cls(customer_id, name, usage_mode, status)


class Customer(Base_Link_Target):
    def __init__(self, customer_id, name, display_name=None, link=None):
        super().__init__(Elements.CUSTOMER, customer_id, display_name, name, link)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        connection_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        link = URL_Link.from_xml_node(get_xml_node(xml_node, Elements.LINK))
        return cls(connection_id, name, display_name, link)


class Device_Info(XML_Object_Base):
    def __init__(self, id_, name, region):
        self.id = id_
        self.name = name
        self.region = region
        super().__init__(Elements.DEVICE_INFO)

    @classmethod
    def from_xml_node(cls, xml_node):
        id_ = get_xml_text_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        region = get_xml_text_value(xml_node, Elements.REGION)

        return cls(id_, name, region)


class Security_Group(XML_Object_Base):
    def __init__(self, uid, name):
        self.uid = uid
        self.name = name
        super().__init__(Elements.SECURITY_GROUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        uid = get_xml_text_value(xml_node, Elements.UID)
        name = get_xml_text_value(xml_node, Elements.NAME)

        return cls(uid, name)


class Security_Groups(XML_List):
    def __init__(self, security_groups):
        super().__init__(Elements.SECURITY_GROUPS, security_groups)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        security_groups = []
        for security_group_node in xml_node.iter(tag=Elements.SECURITY_GROUP):
            security_groups.append(Security_Group.from_xml_node(security_group_node))
        return cls(security_groups)
