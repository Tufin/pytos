
from pytos.securechange.xml_objects.restapi.step.initialize import *


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