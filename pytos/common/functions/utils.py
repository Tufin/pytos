
import collections
import hashlib
import itertools
import logging
import multiprocessing.pool
import os
from socket import error as socket_error

import paramiko

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

logger = logging.getLogger(COMMON_LOGGER_NAME)


def get_range_including_end(start, end):
    return range(start, end + 1)


def split_iterable(iterable, size):
    iterator = iter(iterable)
    item = list(itertools.islice(iterator, size))
    while item:
        yield item
        item = list(itertools.islice(iterator, size))


def convert_timedelta_to_seconds(duration):
    """Convert a timedelta object to to a floating number representing seconds."""
    try:
        return duration.total_seconds()
    except AttributeError:
        message = "Could not convert timedelta {} to seconds floating number.".format(duration)
        logger.error(message)
        raise ValueError(message)


def pid_exists(pid):
    """
    Check if the specified process ID exists.
    :param pid:
    :return:
    """
    try:
        pid = int(pid)
    except TypeError:
        return False
    if pid < 0:
        return False  # NOTE: pid == 0 returns True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:  # errno.ESRCH
        return False  # No such process
    except PermissionError:  # errno.EPERM
        return True  # Operation not permitted (i.e., process exists)
    else:
        return True  # no error, we can send a signal to the process


def parallelize(function, args, num_threads=10):
    """
    Execute the specified function once for each argument in the args_list.
    :param function: The function that will be executed.
    :type function: function
    :param args: An iterable containing the arguments that will be passed to the function.
    :type args: collections.Iterable
    :param num_threads: The maximum number of concurrent executions.
    :type num_threads: int
    """
    thread_pool = multiprocessing.pool.ThreadPool(num_threads)
    logger.debug("Functions arguments are of '%s'('%s').", type(args), args)
    return thread_pool.map(function, args)


def generate_hash(file_name, hash_algo="sha256"):
    """
    Generate a hash for the provided file path.
    :param file_name: The path to the file for which to generate a hash.
    :param hash_algo: The hash algorithm to use.
    :return: The generated hash.
    :rtype: str
    """
    hasher = getattr(hashlib, hash_algo, None)
    if hasher is None:
        raise ValueError("Unknown hash algorithm '{}'.".format(hash_algo))
    with open(file_name, "rb") as file:
        hasher.update(file.read())
        file_hash = hasher.hexdigest()
        return file_hash


def get_ssh_client(host, username, password=None, keyfile=None):
    """
    Returns a connected ssh client using either a password or a keyfile
     :param host: ip of remote host
     :type: str
     :param username:
     :type: str
     :param password:
     :type: str
     :param keyfile: path to local public key file
     :type: str
     :return: A connected ssh client
     :rtype: paramiko.SSHClient
     :raises: ValueError, PermissionError, ConnectionRefusedError
    """
    logger.info("Creating SSH connection to '{}' with user '{}'.".format(host, username))
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if keyfile:
            ssh_client.connect(host, username=username, key_filename=keyfile)
        elif password:
            ssh_client.connect(host, username=username, password=password)
        else:
            raise ValueError('Either password or keyfile must be passed to get_ssh_client.')
    except paramiko.ssh_exception.AuthenticationException:
        raise PermissionError('Incorrect credentials for host {}'.format(host))
    except (paramiko.ssh_exception.SSHException, socket_error) as ex:
        raise ConnectionRefusedError('Could not connect to host {}, error:\n{}'.format(host, str(ex)))
    logger.info('Successfully connected to {}'.format(host))
    return ssh_client


def transfer_file_sftp(ssh_client, local_path, remote_path):
    """
     :param ssh_client:
     :type: paramiko.SSHClient
     :param local_path:
     :type: str
     :param remote_path:
     :type: str
    """
    logger.info("Transferring file '{}' to remote path {}.".format(local_path, remote_path))
    sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
    sftp_client.put(local_path, remote_path)
    logger.info("Done transferring file '{}' to remote path {}.".format(local_path, remote_path))