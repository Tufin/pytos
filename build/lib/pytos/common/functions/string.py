
import argparse
import codecs
import csv
import logging
import re
import string

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

logger = logging.getLogger(COMMON_LOGGER_NAME)


def str_to_bool(bool_string):
    """
    Convert a string value to a corresponding boolean value
    :param bool_string: The string to convert.
    :type bool_string: str
    :rtype: bool
    """
    bool_string = bool_string.lower()
    if bool_string in ["yes", "y", "true", "t", "1", "enable"]:
        return True
    elif bool_string in ["no", "n", "false", "f", "0", "disable"]:
        return False
    else:
        raise ValueError("Cannot resolve '{}' to boolean value.".format(bool_string))


def read_multiline_str_from_stdin():
    """Read a multi-line string from STDIN"""
    input_string = ""
    while True:
        try:
            line = input()
            input_string += "{}\n".format(line)
        except EOFError:
            return input_string


def read_all_args():
    """Read all args from console
    :rtype: tuple"""
    parser = argparse.ArgumentParser()
    parser.add_argument("args", nargs="*")
    cli_args = parser.parse_args()
    return cli_args.args


def get_csv_parser(csv_file, encoding=None, delimiter=None, comment_char=None):
    """
    Read the contents of a file, ignoring any lines that begins with #, and returns a CSV parser for that file.
    :param csv_file: The path to the CSV file that will be parsed or buffer containing the CSV string.
    :type csv_file: str|io.BufferedIOBase
    :return: A CSV parser for the specified file.
    :rtype: _csv.reader
    """
    default_comment_char = "#"
    csv_strings_temp = []
    if comment_char is None:
        comment_char = default_comment_char
    try:
        if hasattr(csv_file, "read"):
            csv_file.seek(0)
            csv_strings = csv_file.read()
            if hasattr(csv_strings, "decode"):
                csv_strings = csv_strings.decode()
            csv_strings = csv_strings.split("\n")
        else:
            if encoding is not None:
                csv_file = codecs.open(csv_file, encoding=encoding)
            else:
                csv_file = open(csv_file)
            csv_strings = csv_file.readlines()
            csv_file.close()
    except (FileNotFoundError, PermissionError) as file_open_error:
        logger.error("Could not open file '%s', error was '%s'.", csv_file, file_open_error)
        raise file_open_error
    for line in csv_strings[:]:
        # Strip comment lines
        if not line.startswith(comment_char) and not line.isspace():
            if any(item.strip() for item in line.split(",")):
                csv_strings_temp.append(line)
    if delimiter is not None:
        csv_reader = csv.reader(csv_strings_temp, delimiter=delimiter)
    else:
        csv_reader = csv.reader(csv_strings_temp)
    return csv_reader


def strip_ansi_codes(ansi_str):
    """
    Strip ANSI codes from a string.
    :param ansi_str: The string from which to strip ANSI codes.
    :return: The string minus ANSI codes.
    :rtype: str
    """
    ansi_escape = re.compile(r'\x1b(?:\[\??|\(|\)|=)[0-9a-zA-Z;<=#]*')
    return ansi_escape.sub('', ansi_str)


def strip_non_printable(line):
    """
    Strip non-printable characters from a line.
    :param line: The line to clean up.
    :return: The stripped line.
    :rtype: str
    """
    line = strip_ansi_codes(line)
    line = ''.join(char for char in line if char in string.printable)
    return line
