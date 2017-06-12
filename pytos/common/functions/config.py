
import configparser
import logging

from pytos.common.logging.definitions import COMMON_LOGGER_NAME
from pytos.common.functions.file_monitor import FileMonitor

logger = logging.getLogger(COMMON_LOGGER_NAME)


class Secure_Config_Parser(configparser.ConfigParser, FileMonitor):
    """This class is used to parse the Tufin PS library configuration files"""
    COMMON = "common"
    CUSTOM = "custom"
    SECURECHANGE = "securechange"
    SECURETRACK = "securetrack"
    LOG_LEVELS = "log_levels"
    DEFAULT_SECTIONS = (COMMON, LOG_LEVELS, SECURETRACK, SECURECHANGE)

    def __init__(self, config_file_path, custom_config_file_path=None):
        configparser.ConfigParser.__init__(self)
        self.config_file_path = config_file_path
        self.custom_config_file_path = custom_config_file_path

        if custom_config_file_path is not None:
            args = (config_file_path, custom_config_file_path)
        else:
            args = (config_file_path, )
        FileMonitor.__init__(self, args)
        self._read_config_files()

    def _read_config_files(self):
        try:
            self.read(self.config_file_path)
        except configparser.Error as config_exception:
            logger.error("Could not parse configuration file '%s'.", self.config_file_path)
            raise config_exception

        if self.custom_config_file_path is not None:
            try:
                self.read(self.custom_config_file_path)
            except configparser.Error:
                logger.error("Could not parse custom configuration file '%s'.", self.custom_config_file_path)

    def _reload_modified_file(self):
        logger.debug("Reloading modified configuration files.")
        self._read_config_files()

    def get(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.get(self, section, option, raw=False, fallback=fallback).strip()
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warning(message)
                raise KeyError(message)
            else:
                return None

    def getint(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getint(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warning(message)
                raise KeyError(message)
            else:
                return None

    def getfloat(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getfloat(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warning(message)
                raise KeyError(message)
            else:
                return None

    def getboolean(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getboolean(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warning(message)
                raise KeyError(message)
            else:
                return None

    def dict(self, section):
        return dict(configparser.ConfigParser.items(self, section))

    def update_config_file(self):
        """
        Write the configuration values from memory to the configuration file.
        """
        logger.info("Updating configuration file '%s' with configuration.", self.config_file_path)
        with open(self.config_file_path, "w") as config_file:
            delimiter = " {} ".format(self._delimiters[0])
            if self._defaults:
                self._write_section(config_file, self.default_section, self._defaults.items(), delimiter)
            for section in self._sections:
                if section in Secure_Config_Parser.DEFAULT_SECTIONS:
                    self._write_section(config_file, section, self._sections[section].items(), delimiter)
