import configparser
import logging

from pytos.common.logging.Defines import COMMON_LOGGER_NAME
from pytos.common.functions.FileMonitor import FileMonitor
from pytos.common.Secret_Store import Secret_Store_Helper

logger = logging.getLogger(COMMON_LOGGER_NAME)


class Secure_Config_Parser(configparser.ConfigParser, FileMonitor):
    """
    This class is used to parse the Tufin PS library configuration files and interact with the Secret_Store_Helper class
     that is used to encrypt credentials.
    """
    COMMON = "common"
    CUSTOM = "custom"
    SECURECHANGE = "securechange"
    SECURETRACK = "securetrack"
    LOG_LEVELS = "log_levels"
    DEFAULT_SECTIONS = (COMMON, LOG_LEVELS, SECURETRACK, SECURECHANGE)

    CONFIG_FILE_PATH = "/opt/tufin/securitysuite/pytos/conf/tufin_api.conf"
    CUSTOM_CONFIG_FILE_PATH = "/opt/tufin/securitysuite/pytos/conf/custom.conf"
    PASSWORD_SUFFIX = "_password"
    USERNAME_SUFFIX = "_username"

    def __init__(self, config_file_path=None, custom_config_file_path=None):
        configparser.ConfigParser.__init__(self)

        if config_file_path is None:
            self.config_file_path = Secure_Config_Parser.CONFIG_FILE_PATH
        else:
            self.config_file_path = config_file_path

        if custom_config_file_path is None:
            self.custom_config_file_path = Secure_Config_Parser.CUSTOM_CONFIG_FILE_PATH
        else:
            self.custom_config_file_path = custom_config_file_path
        FileMonitor.__init__(self, (self.config_file_path, self.custom_config_file_path))

        self._read_config_files()
        self.secret_helper = Secret_Store_Helper()

    def _read_config_files(self):
        try:
            self.read(self.config_file_path)
        except configparser.Error as config_exception:
            logger.error("Could not parse configuration file '%s'.", self.config_file_path)
            raise config_exception
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
                logger.warn(message)
                raise KeyError(message)
            else:
                return None

    def getint(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getint(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warn(message)
                raise KeyError(message)
            else:
                return None

    def getfloat(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getfloat(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warn(message)
                raise KeyError(message)
            else:
                return None

    def getboolean(self, section, option, mandatory=True, raw=False, fallback=object()):
        try:
            return configparser.ConfigParser.getboolean(self, section, option, raw=False, fallback=fallback)
        except (configparser.NoOptionError, configparser.NoSectionError):
            if mandatory:
                message = "Could not find configuration option '%s' in section '%s'." % (option, section)
                logger.warn(message)
                raise KeyError(message)
            else:
                return None

    def dict(self, section):
        return dict(configparser.ConfigParser.items(self, section))

    def _get_encrypted(self, key):
        """
        Get an encrypted value from the Secure Store.
        :param key: The key for the encrypted value to get.
        :type key: str
        """
        try:
            return self.secret_helper.get(key)
        except KeyError:
            return None

    def _set_encrypted(self, key, value):
        """
        Set an encrypted value in the Secure Store.
        :param key: The key for the encrypted value to set.
        :type key: str
        :param value: The value to set for the specified key.
        :type value: str
        """
        return self.secret_helper.set(key, value)

    def get_password(self, key):
        """
        Convenience function that gets a password from the Secure Store (appends the string "_password" to the
        requested key.
        :param key: The key for the encrypted password to get. (The key that will be used is key + "_password")
        :type key: str
        """
        try:
            return self._get_encrypted(key + Secure_Config_Parser.PASSWORD_SUFFIX)
        except KeyError:
            return None

    def set_password(self, key, value):
        """
        Convenience function that sets a password in the Secure Store (appends the string "_password" to the
        requested key.
        :param key: The key for the encrypted password to set. (The key that will be used is key + "_password")
        :type key: str
        """
        return self._set_encrypted(key + Secure_Config_Parser.PASSWORD_SUFFIX, value)

    def get_username(self, key):
        """
        Convenience function that gets a username from the Secure Store (appends the string "_username" to the
        requested key.
        :param key: The key for the encrypted username to get. (The key that will be used is key + "_username")
        :type key: str
        """
        return self._get_encrypted(key + Secure_Config_Parser.USERNAME_SUFFIX)

    def set_username(self, key, value):
        """
        Convenience function that sets a username in the Secure Store (appends the string "_username" to the
        requested key.
        :param key: The key for the encrypted username to set. (The key that will be used is key + "_username")
        :type key: str
        """
        return self._set_encrypted(key + Secure_Config_Parser.USERNAME_SUFFIX, value)

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

    def delete_section(self, section):
        if not self.secret_helper.db:
            msg = "Secret DB file is empty"
            logger.info(msg)
            raise ValueError(msg)

        db = self.secret_helper.db
        for suffix in [Secure_Config_Parser.USERNAME_SUFFIX, Secure_Config_Parser.PASSWORD_SUFFIX]:
            try:
                del db[section + suffix]
            except KeyError as e:
                msg = "Failed to delete section '{}', Error: '{}'".format(section + suffix, e)
                raise KeyError(msg)
        self.secret_helper.write_db_file(db)
