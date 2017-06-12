
import logging
import xml.etree.ElementTree as ET

from pytos.common.logging.definitions import REQUESTS_LOGGER_NAME
from pytos.common.functions.xml import get_xml_text_value

logger = logging.getLogger(REQUESTS_LOGGER_NAME)


class Multiple_Item_Exception(Exception):
    def __init__(self, message, failed_items):
        super().__init__()
        self.message = message
        self.failed_items = failed_items


class Multiple_Create_Exception(Multiple_Item_Exception):
    pass


class Multiple_Update_Exception(Multiple_Item_Exception):
    pass

class Item_Not_Found(Exception):
    def __init__(self, message, item):
        super().__init__()
        self.message = message
        self.item = item


class REST_HTTP_Exception(Exception):
    """
    This is the base REST HTTP exception object from which all other exceptions objects inherit.
    """
    HTTP_STATUS_CODES = {
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing",
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        207: "Multi-Status",
        208: "Already Reported",
        226: "IM Used",
        300: "Multiple Choices",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        305: "Use Proxy",
        306: "Reserved",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Request Entity Too Large",
        414: "Request-URI Too Long",
        415: "Unsupported Media Type",
        416: "Requested Range Not Satisfiable",
        417: "Expectation Failed",
        422: "Unprocessable Entity",
        423: "Locked",
        424: "Failed Dependency",
        426: "Upgrade Required",
        428: "Precondition Required",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
        506: "Variant Also Negotiates",
        507: "Insufficient Storage",
        508: "Loop Detected",
        510: "Not Extended",
        511: "Network Authentication Required"
    }

    def __init__(self, message, status_code, expected_status_code):

        if expected_status_code is None:
            raise ValueError("Expected status code can't be None!")
        try:
            self.status_description = REST_HTTP_Exception.HTTP_STATUS_CODES[status_code]
        except IndexError as indexerror:
            logger.error("Unknown HTTP status code '" + str(status_code) + "'.")
            raise indexerror
        self.message = message
        self.status_code = status_code
        self.expected_status_code = expected_status_code
        super().__init__(message, status_code, expected_status_code)

    def __str__(self):
        exception_string = "\nStatus code: {}\n".format(self.status_code)
        exception_string += "Status: '{}'\n".format(self.status_description)
        exception_string += "Expected status code: {}\n".format(self.expected_status_code)
        exception_string += "Message: '{}'\n".format(self.message)
        return exception_string

    @staticmethod
    def parse_api_message(http_response):
        try:
            error_response_xml = ET.fromstring(http_response.content)
            api_error_message = get_xml_text_value(error_response_xml, "message")
        except (ET.ParseError, AttributeError):
            return None
        else:
            return api_error_message

    @staticmethod
    def get_exception(http_response, expected_status_codes):
        """

        :param http_response:
        :type http_response: requests.models.Response
        :return:
        """
        error_message = REST_HTTP_Exception.parse_api_message(http_response)
        if http_response.status_code == 400:
            exception_class = REST_Bad_Request_Error
        elif http_response.status_code == 401:
            exception_class = REST_Unauthorized_Error
        elif http_response.status_code == 404:
            exception_class = REST_Not_Found_Error
        elif http_response.status_code == 409:
            exception_class = REST_Conflict_Error
        elif http_response.status_code == 412:
            exception_class = REST_Precondition_Failed_Error
        elif http_response.status_code == 414:
            exception_class = REST_Request_URI_Too_Long
        elif http_response.status_code == 500:
            exception_class = REST_Internal_Server_Error
        elif http_response.status_code == 502:
            exception_class = REST_Bad_Gateway
        elif http_response.status_code == 503:
            exception_class = REST_Service_Unavailable_Error
        elif http_response.status_code == 504:
            exception_class = REST_Gateway_Timeout_Error

        else:
            raise ValueError("Exception for status code {} not implemented.".format(http_response))
        return exception_class(error_message, expected_status_codes)


class REST_Client_Error(REST_HTTP_Exception):
    def __init__(self, message, status_code, expected_status_code):
        super().__init__(message, expected_status_code, status_code)


class REST_Server_Error(REST_HTTP_Exception):
    def __init__(self, message, status_code, expected_status_code):
        super().__init__(message, expected_status_code, status_code)


class REST_Bad_Request_Error(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=400):
        super().__init__(message, expected_status_code, status_code)


class REST_Unauthorized_Error(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=401):
        super().__init__(message, expected_status_code, status_code)


class REST_Not_Found_Error(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=404):
        super().__init__(message, expected_status_code, status_code)


class REST_Conflict_Error(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=409):
        super().__init__(message, expected_status_code, status_code)


class REST_Precondition_Failed_Error(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=412):
        super().__init__(message, expected_status_code, status_code)


class REST_Request_URI_Too_Long(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=414):
        super().__init__(message, expected_status_code, status_code)


class REST_Internal_Server_Error(REST_Server_Error):
    def __init__(self, message, expected_status_code, status_code=500):
        super().__init__(message, expected_status_code, status_code)


class REST_Bad_Gateway(REST_Internal_Server_Error):
    def __init__(self, message, expected_status_code, status_code=502):
        super().__init__(message, expected_status_code, status_code)


class REST_Service_Unavailable_Error(REST_Internal_Server_Error):
    def __init__(self, message, expected_status_code, status_code=503):
        super().__init__(message, expected_status_code, status_code)


class REST_Gateway_Timeout_Error(REST_Server_Error):
    def __init__(self, message, expected_status_code, status_code=504):
        super().__init__(message, expected_status_code, status_code)

class ItemAlreadyExists(REST_Client_Error):
    def __init__(self, message, expected_status_code, status_code=400):
        super().__init__(message, expected_status_code, status_code)
