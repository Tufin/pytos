
import abc

class URLParamBuilderInterface(metaclass=abc.ABCMeta):
    """Interface for classes that would build parameter filters for URI"""

    def build(self, *, prepend_question_mark=True):
        """
        :param prepend_question_mark: Prepend a '?' to the returned uri params part
        :type prepend_question_mark: bool
        :return: str
        """
        raise NotImplementedError

    def set(self, key, value):
        """Set or overwrite parameter to be used in building parameters filers for uri
        :param key: The name of the parameter
        :type key: str
        :param value: The value of the parameter
        :type value: str|int|bool
        """
        raise NotImplementedError


class URLParamBuilderDict(URLParamBuilderInterface):
    """The Parameter builder for URI from dictionary"""
    def __init__(self, params):
        """
        :param params: dictionary with name: value
        :type params: dict
        """
        if params:
            self.params = params
        else:
            self.params = {}

    def build(self, *, prepend_question_mark=True):
        if not self.params:
            return ""
        filter_params = "&".join("{}={}".format(key, value) for key, value in self.params.items())
        if prepend_question_mark:
            filter_params = "?{}".format(filter_params)
        return filter_params

    def set(self, key, value):
        if not key:
            raise ValueError("Key can't be empty")
        self.params.update({key: value})