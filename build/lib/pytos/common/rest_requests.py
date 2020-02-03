
import collections
import datetime
import hashlib
import http.cookiejar
import logging
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from enum import Enum

import requests
import requests.exceptions
import requests.packages.urllib3
import requests_toolbelt
from requests.auth import HTTPDigestAuth

from pytos.common.logging.definitions import REQUESTS_LOGGER_NAME
from pytos.common.exceptions import REST_HTTP_Exception, REST_Bad_Gateway, REST_Service_Unavailable_Error
from pytos.common.functions.xml import get_xml_text_value

requests.packages.urllib3.disable_warnings()
try:
    from xml.etree.ElementTree import ParseError
except ImportError:
    from xml.parsers.expat import ExpatError as ParseError

# Uncomment the two lines below to get more debugging information from httplib
# import http.client
# http.client.HTTPConnection.debuglevel = 1
logger = logging.getLogger(REQUESTS_LOGGER_NAME)


class RESTAuthMethods(Enum):
    Digest = "digest"
    Basic = "basic"


class REST_Request(object):
    """
    This class is the base class from which all other Request objects inherit.
    :cvar TIMEOUT: The default timeout for requests.
    :cvar MAX_RETRIES: The default amount of times to retry requests that result in connection errors.
    :cvar RETRY_INTERVAL: The default interval between request retries, in seconds.
    :cvar RETRY_BACKOFF: The default exponential backoff for retries.
    """
    RETRY_BACKOFF = 2
    TIMEOUT = 300
    MAX_RETRIES = 5
    RETRY_INTERVAL = 5
    MAX_URI_LENGTH = 6500

    def __init__(self, hostname, uri, protocol="https", **kwargs):
        """
        Constructor for REST_Request
        :param uri: The URI the request will access.
        :type uri: str
        :param protocol: The protocol the request will use.
        :type protocol: str
        :keyword timeout: (Optional) Set the timeout for the request (Default is 300 seconds).
        :type timeout: float
        :keyword login_data: The username and password that will be used for HTTP basic authentication for the request
        ({"username" : username,"password" : password})
        :type login_data: dict
        :keyword verify_ssl: If set to False, SSL verification for requests is disabled, otherwise it is enabled.
        :type verify_ssl: bool
        :keyword cookies: If set, the contents will be appended to the cookies sent with the request.
        :type cookies: str/dict/cookielib.CookieJar
        :keyword headers: Headers to be sent with the request.
        :type headers: dict
        :keyword max_retries: The amount of times to retry the request if a connection error occurs.
        :type max_retries: int
        :keyword retry_interval: The interval between retries in seconds.
        :type retry_interval: int
        :keyword retry_backoff: The exponential backoff for retries.
        :type retry_backoff: int
        :keyword expected_status_codes: A single integer or a list of integers representing HTTP status codes.
        :type expected_status_codes: int or list of ints
        :raise REST_HTTP_Exception If expected_status_codes is specified, if the response does not contain at least one
        of the status codes, a REST_HTTP_Exception is raised.
        :raise requests.exceptions.Timeout: If a timeout error occurs while trying to perform the request.
        :raise requests.exceptions.ConnectionError: If an error occurs while trying to connect the specified host.
        """
        self.response, self.request = None, None
        self.expected_status_codes = None
        self.body = None
        self.auth_method = kwargs.get("auth_method", RESTAuthMethods.Basic)
        if protocol not in ["http", "https"]:
            raise ValueError("Protocol must be either http or https!")
        else:
            self.protocol = protocol

        verify_ssl = kwargs.get("verify_ssl")
        if verify_ssl is not None:
            logger.debug("Setting verify_ssl to '%s'", verify_ssl)
            self.verify_ssl = verify_ssl
        else:
            logger.debug("verify_ssl not set, setting to True by default.")
            self.verify_ssl = True

        session = kwargs.get("session")
        if session is None:
            self.session = requests.Session()
        else:
            self.session = session

        proxies = kwargs.get("proxies")
        if proxies is not None:
            self.session.proxies = proxies

        self.hostname = hostname

        uri_length = len(uri)
        if uri_length <= REST_Request.MAX_URI_LENGTH:
            self.uri = uri
        else:
            raise ValueError("Maximum URI length ({}) exceeded , current URI length is {}, URI is '{}'".format(
                REST_Request.MAX_URI_LENGTH, uri_length, uri))

        login_data = kwargs.get("login_data")
        if login_data is not None:
            if all(login_data.values()):
                if self.auth_method == RESTAuthMethods.Digest:
                    self.auth_tuple = HTTPDigestAuth(login_data["username"], login_data["password"])
                else:
                    password_hash = hashlib.sha256()
                    password_hash.update(login_data["password"].encode("ascii"))
                    password_hash = password_hash.hexdigest()
                    logger.debug("Setting login_data to username '%s', SHA256 hashed password '%s'.",
                                 login_data["username"], password_hash)
                    self.auth_tuple = (login_data["username"], login_data["password"])
            else:
                raise ValueError("Both username and password must be set.")
        else:
            self.auth_tuple = None

        timeout = kwargs.get("timeout")
        if timeout is not None:
            logger.debug("Setting request timout to '%s'", timeout)
            self.timeout = timeout
        else:
            self.timeout = REST_Request.TIMEOUT

        max_retries = kwargs.get("max_retries")
        if max_retries is not None:
            logger.debug("Setting maximum retry count to '%s'", max_retries)
            self.max_retries = max_retries
        else:
            self.max_retries = REST_Request.MAX_RETRIES

        retry_backoff = kwargs.get("retry_backoff")
        if retry_backoff is not None:
            logger.debug("Setting retry backoff multiplier to '%s'", retry_backoff)
            self.retry_backoff = retry_backoff
        else:
            self.retry_backoff = REST_Request.RETRY_BACKOFF

        retry_interval = kwargs.get("retry_interval")
        if retry_interval is not None:
            logger.debug("Setting retry interval to '%s'", retry_interval)
            self.retry_interval = retry_interval
        else:
            self.retry_interval = REST_Request.RETRY_INTERVAL

        expected_status_codes = kwargs.get("expected_status_codes")
        if expected_status_codes is not None:
            logger.debug("Setting expected_status_codes to '%s'", expected_status_codes)
            self.expected_status_codes = expected_status_codes

        cookies = kwargs.get("cookies")
        if cookies is not None:
            logger.debug("Setting cookies to '%s'", cookies)
            if isinstance(cookies, http.cookiejar.CookieJar):
                self.cookie_jar = cookies
            else:
                logger.warning("Unknown cookie type '%s'", type(cookies))
                self.cookie_jar = http.cookiejar.CookieJar
        else:
            self.cookie_jar = http.cookiejar.CookieJar

        headers = kwargs.get("headers")
        self.headers = {}
        if headers is not None:
            self.headers.update(headers)
            logger.debug("Setting headers to '%s'", headers)
        self.url = "{protocol}://{hostname}{uri}".format(protocol=self.protocol, hostname=self.hostname, uri=self.uri)

    def get_created_item_id(self):
        try:
            item_id = self.response.headers["location"].split("/")[-1]
            if "?" in item_id:
                logger.debug("ID contains a reference to a parameter.")
                item_id = re.sub(r"\?.*", "", item_id)
            if "-" in item_id:
                logger.debug("ID refers to a task.")
                return item_id
            elif item_id[0].isalpha():
                logger.debug("ID refers to a name.")
                return item_id
            elif "," in item_id:
                return [int(item) for item in item_id.split(",")]
            return int(item_id)
        except (AttributeError, KeyError):
            return None

    def _ensure_response_status(self):
        """Check if the self.response object contains at least one of HTTP status code in self.expected_status_codes.
        :return: Returns True if the specified status code was found in the self.response member object.
        :rtype: bool
        @raise requests.HTTPError: If the specified status code was not found in the self.response member object.
        """
        status_code_ok = True
        if not self.expected_status_codes:
            return True
        try:
            self.response.raise_for_status()
        except requests.exceptions.HTTPError as local_request_exception:
            request_exception = local_request_exception
            logger.error("Got the following error while performing request: '%s'.", request_exception)
            status_code_ok = False

        if status_code_ok:
            if isinstance(self.expected_status_codes, collections.Iterable):
                if self.response.status_code not in self.expected_status_codes:
                    status_code_ok = False
            elif isinstance(self.expected_status_codes, int):
                if self.expected_status_codes != self.response.status_code:
                    status_code_ok = False
            else:
                raise ValueError("self.expected_status_codes must either be an int or list of ints.")

        if not status_code_ok:
            error_message = ""
            try:
                error_response_xml = ET.fromstring(self.response.content)
                api_error_message = get_xml_text_value(error_response_xml, "message")
                api_error_code = error_response_xml.find("code").text
                if api_error_message is not None:
                    error_message = "Message from API is '{}'.\n".format(api_error_message)
                    logger.error(error_message)
                error_message += "Error from API is '{}'.".format(api_error_code)
                logger.error(error_message)
            except (ParseError, AttributeError):
                error_message = "Could not parse response from API."
                logger.error(error_message)
            logger.error("Status code for request is '%s'.", self.response.status_code)
            http_exception = REST_HTTP_Exception.get_exception(self.response, self.expected_status_codes)
            raise http_exception
        else:
            logger.info("Status code for request is '%s'.", self.response.status_code)
            return True

    def _perform_request(self):
        start_time = datetime.datetime.now()
        exception_copy = None
        for retry_count in range(self.max_retries + 1):
            try:
                self.response = self.session.send(self.request, verify=self.verify_ssl, timeout=self.timeout)
            except requests.exceptions.SSLError as request_exception:
                exception_copy = request_exception
                logger.error("Connection to '%s://%s%s' failed ('%s').", self.protocol, self.hostname, self.uri,
                             request_exception.args[0])
            except requests.exceptions.ConnectionError as request_exception:
                exception_copy = request_exception
                message = "Connection to {}://{}{} failed."
                try:
                    message = message.format(self.protocol, self.hostname, self.uri, request_exception.args[0].reason)
                except AttributeError:
                    message = message.format(self.protocol, self.hostname, self.uri, request_exception.args[0])
                logger.error(message)
            except requests.exceptions.Timeout as request_exception:
                exception_copy = request_exception
                logger.error("Connection to '%s://%s%s' timed out ('%s' seconds).", self.protocol, self.hostname,
                             self.uri,
                             self.timeout)
            else:
                logger.debug("Sent headers: '%s.", self.headers)
                if self.body is not None:
                    logger.debug("Sent body: '%s'.", self.body)
                try:
                    self._ensure_response_status()
                    request_duration = datetime.datetime.now() - start_time
                    logger.debug("Request took '%s' seconds.", request_duration)
                    logger.info("Received status: '%s'.", self.response.status_code)
                    logger.debug("Received headers: '%s'.", self.response.headers)
                    if self.response.content:
                        logger.debug("Received response body: '%s'", self.response.content)
                    break
                except (REST_Bad_Gateway, REST_Service_Unavailable_Error) as request_exception:
                    exception_copy = request_exception
                    self.log_error_details(request_exception)
                except REST_HTTP_Exception as request_exception:
                    exception_copy = request_exception
                    self.log_error_details(request_exception)
                    break

            logger.debug("Sleeping for '%s' seconds between retries.", self.retry_interval)
            time.sleep(self.retry_interval)
            logger.info("Retrying request to '%s', Retry '%s' out of '%s'.", self.url, retry_count + 1,
                        self.max_retries)
            if self.retry_backoff != 1:
                self.retry_interval *= self.retry_backoff
                logger.debug("Multiplied retry interval with backoff ('%s'), retry_interval is now '%s'.",
                             self.retry_backoff, self.retry_interval)

        if exception_copy is not None:
            raise exception_copy

    def log_error_details(self, request_exception):
        logger.error("Request to '%s://%s%s' resulted in an error from the server: '%s'.",
                     self.protocol,
                     self.hostname,
                     self.uri, request_exception)
        logger.error("Sent headers: '%s.", self.headers)
        if self.body is not None:
            logger.error("Sent body: '%s'.", self.body)
        logger.error("Received headers: '%s'.", self.response.headers)
        if self.response.content:
            logger.error("Received response body: '%s'", self.response.content)

    def _encode_body_params(self, params):
        logger.debug("Params: '%s'.", params)
        for index, key in enumerate(params.keys()):
            if index == 0:
                self.body = "{}={}".format(key, urllib.parse.quote_plus(str(params[key])))
            else:
                self.body += "&{}={}".format(key, urllib.parse.quote_plus(str(params[key])))


class GET_Request(REST_Request):
    """
    This class wraps a requests GET request.
    """

    def __init__(self, hostname, uri, protocol="https", **kwargs):
        """
        Constructor
        """
        super().__init__(hostname, uri, protocol, **kwargs)
        logger.info("Sending GET request to '%s'", self.url)
        request_obj = requests.Request("GET", self.url, auth=self.auth_tuple,
                                       params=kwargs.get("params"), headers=self.headers)
        if self.session:
            self.request = self.session.prepare_request(request_obj)
        else:
            self.request = request_obj.prepare()
        self._perform_request()


class POST_Request(REST_Request):
    """
    This class wraps a requests POST request.
    """

    def __init__(self, hostname, uri, body=None, protocol="https", cgi=False, **kwargs):
        """
        Constructor
        :param body: Body contents to be sent with the request
        :type body: str|dict
        :param cgi: If set to True, the content type header for the request will be set to
         "application/x-www-form-urlencoded", otherwise it will be set to "application/xml"
        :type cgi: bool
        :keyword params: If set, these parameters that will be URL encoded and included in the request body.
        :type params: dict
        :keyword multi_part_form_params: A tuple of parameters that will be encoded in multipart/form encoding.
        If the tuple contains 2 items, the first one will be used as the parameter name, the second
        will be the parameter value.
        If the tuple contains 3 items, the first will be used as the parameter name, the second will
        be a open file handle, the third will be the name for the file to be sent.
        :type multi_part_form_params: tuple
        """
        super().__init__(hostname, uri, protocol, **kwargs)

        # Handle parameters in dict form
        params = kwargs.get("params")

        # Handle files
        files = kwargs.get("files")

        # Handle multi part params
        multi_part_form_params = kwargs.get("multi_part_form_params")
        if multi_part_form_params is not None:
            logger.debug("Got the following multi-part form params '%s'", multi_part_form_params)

        data_types = (params, multi_part_form_params, body)
        true_count = sum([1 for data_type in data_types if data_type])
        if true_count > 1:
            raise ValueError("Only one data type to be sent can be used: body, params or multi_part_form_params.")

        if multi_part_form_params is not None:
            multi_part_form = requests_toolbelt.MultipartEncoder(fields=multi_part_form_params)
            self.headers["Content-Type"] = multi_part_form.content_type
            self.body = multi_part_form.to_string()
            multi_part_form_length = str(multi_part_form.len) if hasattr(multi_part_form, 'len') else len(multi_part_form)
            self.headers["Content-Size"] = multi_part_form_length
            self.headers["Accept"] = "*/*"
        else:
            if params is not None:
                self._encode_body_params(params)
            else:
                self.body = body
            if "Content-Type" not in self.headers:
                if cgi:
                    self.headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    self.headers["Content-Type"] = "application/xml"

        logger.info("Sending POST request to '%s'", self.url)
        request_obj = requests.Request("POST", self.url, data=self.body, auth=self.auth_tuple, headers=self.headers,
                                       files=files)
        if self.session:
            self.request = self.session.prepare_request(request_obj)
        else:
            self.request = request_obj.prepare()
        self._perform_request()


class PUT_Request(REST_Request):
    """
    This class wraps a requests PUT request.
    """

    def __init__(self, hostname, uri, body=None, protocol="https", cgi=False, **kwargs):
        """
        Constructor
        :param body: Body contents to be sent with the request
        :type body: str|dict
        :param cgi: If set to True, the content type header for the request will be set to
        "application/x-www-form-urlencoded", otherwise it will be set to "application/xml"
        :type cgi: bool
        :keyword params: If set, these parameters that will be URL encoded and included in the request body.
        :type params: dict
        """
        super().__init__(hostname, uri, protocol, **kwargs)
        # Handle parameters in dict form
        params = kwargs.get("params")
        data_types = (params, body)
        true_count = sum([1 for data_type in data_types if data_type])
        if true_count > 1:
            raise ValueError("Only one data type to be POSTed can be used: body or params.")
        if params is not None:
            self._encode_body_params(params)
        else:
            self.body = body

        if self.body is not None:
            if "Content-Type" not in self.headers:
                if cgi:
                    self.headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    self.headers["Content-Type"] = "application/xml"
        logger.info("Sending PUT request to '%s'", self.url)
        request_obj = requests.Request("PUT", self.url, data=self.body, auth=self.auth_tuple, headers=self.headers)
        if self.session:
            self.request = self.session.prepare_request(request_obj)
        else:
            self.request = request_obj.prepare()
        self._perform_request()


class DELETE_Request(REST_Request):
    """
    This class wraps a requests DELETE request.
    """

    def __init__(self, hostname, uri, protocol="https", cgi=False, **kwargs):
        """
        Constructor
        :param cgi: If set to True, the content type header for the request will be set to
        "application/x-www-form-urlencoded", otherwise it will be set to "application/xml"
        :type cgi: bool
        """
        super().__init__(hostname, uri, protocol, **kwargs)
        if "Content-Type" not in self.headers:
            if cgi:
                self.headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                self.headers["Content-Type"] = "application/xml"
        logger.info("Sending DELETE request to '%s'", self.url)
        request_obj = requests.Request("DELETE", self.url, auth=self.auth_tuple, headers=self.headers)
        if self.session:
            self.request = self.session.prepare_request(request_obj)
        else:
            self.request = request_obj.prepare()
        self._perform_request()
