from pytos.common.Base_Types import SubclassRegistry


class ToolsBase(metaclass=SubclassRegistry):
    TOOL_URL_BASE = "/ps/tools/"
    _URL_PART = ""
    _NAME = "ToolsBase"

    @classmethod
    def get_name(cls):
        return cls._NAME

    @classmethod
    def get_registered_tools(cls):
        return sorted(cls.registry, key=lambda report: str(report.__name__))

    @classmethod
    def get_tool_url(cls):
        return cls.TOOL_URL_BASE + cls._URL_PART
