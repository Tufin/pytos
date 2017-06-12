
import http.cookiejar
import logging
import multiprocessing

from pytos.common import rest_requests
from pytos.common.logging.definitions import HELPERS_LOGGER_NAME
from pytos.common.functions import get_local_ip_addresses

logger = logging.getLogger(HELPERS_LOGGER_NAME)


def verify_is_running_on_localhost(func):
    def func_wrapper(self, *args):
        if not self._is_running_on_localhost():
            raise IOError("This method can only be used when running on the local TOS installation.")
        else:
            return func(self, *args)

    return func_wrapper


class Secure_API_Helper:
    """
    This class is a base class that is used to interact via HTTP with the various TSS products.
    It also allows for easy sending of email messages.
    This class is not meant to be used on its own, but rather as a base class for the other helper classes, each
    specific to SecureTrack,SecureChange or SecureApp.

    :cvar LOGIN_COOKIE_TIMEOUT_SECONDS: The amount of time in seconds that the login cookie is valid for.
    """
    NUM_API_THREADS = multiprocessing.cpu_count()
    LOGIN_COOKIE_TIMEOUT_SECONDS = 120
    CONFIG_PARSER_SECTION_NAME = "securetrack"

    def __init__(self, hostname, login_data, timeout=None, max_retries=None):
        """Constructor

        :param hostname: The hostname with which we will communicate with HTTP.
        :type hostname: str
        :param login_data: A tuple of (username,password) used for basic authentication with the specified hostname.
        :type login_data: tuple
        :keyword timeout: (Optional) The timeout in seconds for HTTP requests.
        :type timeout: int
        :keyword max_retries: (Optional) The retries count of request failure.
        :type max_retries: int
        """
        self.hostname = hostname
        if self.hostname == "127.0.0.1":
            self._real_hostname = get_local_ip_addresses()[0]
        else:
            self._real_hostname = hostname
        self.login_data = {"username": login_data[0], "password": login_data[1]}
        self.cookie_jar = http.cookiejar.CookieJar()
        self._application_url = None
        self.max_retries = max_retries
        self.timeout = timeout

    def _is_running_on_localhost(self):
        if self.hostname.startswith("127.0.0.1") or self.hostname.startswith("localhost"):
            return True
        else:
            return False

    def get_uri(self, uri, expected_status_codes=None, headers=None, timeout=None, max_retries=None, session=None):
        """Make a GET request to a URI for the configured host.

        :param uri: The URI relative to the configured host to GET.
        :type uri: str
        :keyword expected_status_codes: (Optional) An integer or a list of integers representing HTTP status codes.
        :type expected_status_codes: int or list of ints
        :keyword timeout: (Optional) Set the timeout for the request.
        :type timeout: float
        :return: A response object for the GET request.
        """
        if headers is None:
            headers = {}
        expected_status_codes = expected_status_codes
        timeout = timeout
        if timeout is None:
            timeout = self.timeout
        if max_retries is None:
            max_retries = self.max_retries

        get_request = rest_requests.GET_Request(self._real_hostname, uri, login_data=self.login_data,
                                                headers=headers, verify_ssl=False,
                                                expected_status_codes=expected_status_codes,
                                                timeout=timeout, cookies=self.cookie_jar,
                                                session=session, max_retries=max_retries)
        return get_request

    def post_uri(self, uri, body=None, params_dict=None, multi_part_form_params=None, expected_status_codes=None,
                 cgi=None, headers=None, timeout=None, session=None):
        """Make a POST request to a URI for the configured host.

        :param headers: Additional headers to add to the request.
        :param uri: The URI relative to the configured host to POST.
        :type uri: str
        :param body: The string that will be used as the body for the POST request.
        :type body: str|bytes
        :param params_dict: A dictionary of params that will be used in the request body in the form of /URI?key=value.
        :type params_dict: dict
        :param multi_part_form_params: A tuple of parameters that will be encoded in multipart/form encoding.
            If the tuple contains 2 items, the first one will be used as the parameter name, the second will be the
            value.
            If the tuple contains 3 items, the first will be used as the parameter name, the second will be a open file
            handle, the third will be the name for the file to be sent.
        :type multi_part_form_params: tuple|int|dict
        :keyword expected_status_codes: (Optional) An integer or a list of integers representing HTTP status codes.
        :type expected_status_codes: int |list[int]
        :keyword cgi: (Optional) POST in CGI mode.
        :type cgi: bool
        :keyword timeout: (Optional) Set the timeout for the request.
        :type timeout: float
        :return: A response object for the POST request.
        """
        if headers is None:
            headers = {}
        timeout = timeout
        if timeout is None:
            timeout = self.timeout

        if params_dict:
            post_request = rest_requests.POST_Request(self._real_hostname, uri, body, cgi=cgi,
                                                      params=params_dict, headers=headers,
                                                      verify_ssl=False,
                                                      expected_status_codes=expected_status_codes,
                                                      timeout=timeout, cookies=self.cookie_jar,
                                                      session=session)
        else:
            if multi_part_form_params is not None:
                logger.debug("Sending multi part request, data is " + str(multi_part_form_params))
                post_request = rest_requests.POST_Request(self._real_hostname, uri, body, headers=headers,
                                                          multi_part_form_params=multi_part_form_params,
                                                          cgi=cgi, login_data=self.login_data,
                                                          verify_ssl=False,
                                                          expected_status_codes=expected_status_codes,
                                                          timeout=timeout, cookies=self.cookie_jar,
                                                          session=session)
            else:
                logger.debug("Sending regular POST.")
                post_request = rest_requests.POST_Request(self._real_hostname, uri, body, headers=headers,
                                                          login_data=self.login_data, verify_ssl=False,
                                                          expected_status_codes=expected_status_codes,
                                                          timeout=timeout, cookies=self.cookie_jar,
                                                          session=session, cgi=cgi)
        return post_request

    def put_uri(self, uri, body=None, expected_status_codes=None, headers=None, timeout=None,
                session=None):
        """Make a PUT request to a URI for the configured host.

        :param uri: The URI relative to the configured host to PUT.
        :type uri: str
        :param body: The string that will be used as the body for the PUT request.
        :type body: str|bytes
        :param params_dict: A dictionary of params that will be used in the request body in the form of /URI?key=value.
        :type params_dict: dict
        :keyword expected_status_codes: (Optional) An integer or a list of integers representing HTTP status codes.
        :type expected_status_codes: int| list[int]
        :keyword timeout: (Optional) Set the timeout for the request.
        :type timeout: float
        :return: A response object for the PUT request.
        """
        if headers is None:
            headers = {}
        timeout = timeout
        if timeout is None:
            timeout = self.timeout

        put_request = rest_requests.PUT_Request(self._real_hostname, uri, body, headers=headers,
                                                login_data=self.login_data, verify_ssl=False,
                                                expected_status_codes=expected_status_codes,
                                                timeout=timeout, cookies=self.cookie_jar,
                                                session=session)
        return put_request

    def delete_uri(self, uri, headers=None, session=None, **kwargs):
        """Make a DELETE request to a URI for the configured host.

        :param uri: The URI relative to the configured host to DELETE.
        :type uri: str
        :keyword expected_status_codes: (Optional) An integer or a list of integers representing HTTP status codes.
        :type expected_status_codes: int|list[int]
        :keyword timeout: (Optional) Set the timeout for the request.
        :type timeout: float
        :return: A response object for the DELETE request.
        """
        expected_status_codes = kwargs.get("expected_status_codes")
        if headers is None:
            headers = {}
        timeout = kwargs.get("timeout")
        if timeout is None:
            timeout = self.timeout

        delete_request = rest_requests.DELETE_Request(self._real_hostname, uri, headers=headers,
                                                      login_data=self.login_data, verify_ssl=False,
                                                      expected_status_codes=expected_status_codes,
                                                      timeout=timeout, cookies=self.cookie_jar,
                                                      session=session)
        return delete_request

    @classmethod
    def from_secure_config_parser(cls, secure_config_parser_obj, **kwlist):
        hostname = secure_config_parser_obj.get(cls.CONFIG_PARSER_SECTION_NAME, "hostname")
        username = secure_config_parser_obj.get_username(cls.CONFIG_PARSER_SECTION_NAME)
        password = secure_config_parser_obj.get_password(cls.CONFIG_PARSER_SECTION_NAME)
        return cls(hostname, (username, password), **kwlist)