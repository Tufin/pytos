
import xml.sax.saxutils

from pytos.common.base_types import XML_Object_Base, XML_List
from pytos.common.definitions import xml_tags


class Step_Field_Base(XML_Object_Base):
    FIELD_CONTENT_ATTRIBUTES = None

    def __init__(self, num_id, name, read_only=None):
        super().__init__(xml_tags.Elements.FIELD)
        self.set_attrib(xml_tags.NAMESPACE_FIELD_ATTRIB_CONTENT, xml_tags.XSI_NAMESPACE_URL)
        self.id = num_id
        self.name = name
        self.read_only = read_only

    def get_field_type(self):
        try:
            return self._attribs[xml_tags.Attributes.XSI_TYPE]
        except KeyError:
            raise KeyError("Could not find type attribute, existing attributes: {}".format(self._attribs))

    def get_field_value(self):
        """
        Get the value(s) of a field.
        If the field type contains more than one content attribute, the output will be a dictionary.
        """
        attribute_names = self.__class__.FIELD_CONTENT_ATTRIBUTES
        if isinstance(attribute_names, list):
            values_dict = {}
            for attribute_name in attribute_names:
                attribute_value = self.__dict__.get(attribute_name)
                if isinstance(attribute_value, str):
                    values_dict[attribute_name] = xml.sax.saxutils.unescape(attribute_value)
                else:
                    values_dict[attribute_name] = attribute_value
            return values_dict
        else:
            if isinstance(self.__dict__[attribute_names], str):
                return xml.sax.saxutils.unescape(self.__dict__.get(attribute_names))
            else:
                return self.__dict__.get(attribute_names)

    def set_field_value(self, value):
        """
        Set the value(s) of a field.
        If the field type contains more than one content attribute, the input must be a dictionary.
        """
        attribute_names = self.__class__.FIELD_CONTENT_ATTRIBUTES
        if isinstance(attribute_names, list):
            if not isinstance(value, dict):
                raise TypeError("For field types with more than one content attribute, value must be a dict.")
            for attribute_name in attribute_names:
                try:
                    if isinstance(value[attribute_name], str):
                        self.__dict__[attribute_name] = xml.sax.saxutils.escape(value[attribute_name])
                    else:
                        self.__dict__[attribute_name] = value[attribute_name]
                except KeyError:
                    continue
        else:
            if isinstance(self.__dict__[attribute_names], str):
                self.__dict__[attribute_names] = xml.sax.saxutils.escape(value)
            else:
                self.__dict__[attribute_names] = value

    def from_xml_node(self, xml_node):
        raise NotImplementedError

    def __str__(self):
        field_value = self.get_field_value()
        field_string = "{}:\n".format(self.name)
        if field_value:
            if isinstance(field_value, dict):
                for key, value in field_value.items():
                    field_string += "\t{}: {}\n".format(key, value)
            else:
                field_string = "{}: {}\n".format(self.name, field_value)
        return field_string


class Step_Multi_Field_Base(Step_Field_Base):
    def __init__(self, num_id, name, read_only=None):
        super().__init__(num_id, name, read_only)

    def from_xml_node(self, xml_node):
        raise NotImplementedError

    def set_field_value(self, values):
        """
        Set the value(s) of a field.
        If the field type contains more than one content attribute, the input must be a dictionary.
        """
        attribute_names = self.__class__.FIELD_CONTENT_ATTRIBUTES
        if isinstance(attribute_names, list):
            if not isinstance(values, dict):
                raise TypeError("For field types with more than one content attribute, values must be a dict.")
            value_dict = {}
            for key, value in values.items():
                if isinstance(value, list):
                    escaped_values = []
                    for item in value:
                        if isinstance(item, str):
                            escaped_values.append(xml.sax.saxutils.escape(item))
                        else:
                            escaped_values.append(item)
                    value_dict[key] = escaped_values
                elif isinstance(value, str):
                    value_dict[key] = xml.sax.saxutils.escape(value)
                else:
                    value_dict[key] = value
            super().set_field_value(value_dict)
        else:
            if isinstance(values, XML_List):
                super().set_field_value(values)
            else:
                escaped_values = []
                for value in values:
                    if isinstance(value, str):
                        escaped_values.append(xml.sax.saxutils.escape(value))
                    else:
                        escaped_values.append(value)
                super().set_field_value(escaped_values)

    def get_field_value(self):
        attribute_names = self.__class__.FIELD_CONTENT_ATTRIBUTES
        if isinstance(attribute_names, list):
            value_dict = {}
            for key, value in super().get_field_value().items():
                if isinstance(value, str):
                    value_dict[key] = xml.sax.saxutils.escape(value)
                else:
                    value_dict[key] = value
            return value_dict
        else:
            unescaped_values = []
            field_value = super().get_field_value()
            try:
                if isinstance(field_value, XML_List):
                    return field_value
                else:
                    for item in super().get_field_value():
                        if isinstance(item, str):
                            unescaped_values.append(xml.sax.saxutils.unescape(item))
                        else:
                            unescaped_values.append(item)
            except TypeError:
                return field_value
            else:
                return unescaped_values

    def __str__(self):
        field_values = []
        field_string = "{}: \n".format(self.name)
        try:
            for value in self.get_field_value():
                try:
                    value = str(value).strip()
                except AttributeError:
                    pass
                field_values.append(value)
        except TypeError:
            pass
        field_values = [value for value in field_values if value]
        for index, value in enumerate(field_values):
            field_string += "\t{}. {}\n".format(index + 1, value)
        return field_string


class Target_Base(XML_Object_Base):
    def __init__(self, xml_tag, num_id, target_type=""):
        super().__init__(xml_tag)
        self.set_attrib(xml_tags.TYPE_ATTRIB, target_type)
        self.id = num_id

    def get_target_type(self):
        return self._attribs[xml_tags.TYPE_ATTRIB]

    def from_xml_node(self, xml_node):
        raise NotImplementedError


class Access_Request_Target(Target_Base):
    def __init__(self, xml_tag, num_id, target_type, region=None):
        self.region = region
        super().__init__(xml_tag, num_id, target_type)

    def to_pretty_str(self):
        raise NotImplementedError

    def from_xml_node(self, xml_node):
        raise NotImplementedError
