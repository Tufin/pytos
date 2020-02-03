import collections
import hashlib
import itertools
import logging
import multiprocessing.pool
import os
from socket import error as socket_error

import fcntl
import paramiko
import time

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

logger = logging.getLogger(COMMON_LOGGER_NAME)


class FileLock:
    """
    Simple implementation of the file lock based on fcntl.lock.
    Can be both blocking and not.
    """

    DEFAULT_FILE_LOCK_PATH = "/tmp/"

    def __init__(self, lock_file_name, *, blocking=False, lock_folder=None):
        """Constructor

        :param lock_file_name: The name of the file to be used.
        :type lock_file_name: str|int
        :keyword blocking: (Optional) If to wait for release or to fail if already blocked. Default: False
        :type blocking: bool
        :keyword lock_folder: (Optional) Specify custom path to the folder for lock.
        :type lock_folder: str
        """
        # Make it String as it might be passed as ticket id
        self.lock_file_name = str(lock_file_name)
        if not self.lock_file_name.endswith(".lock"):
            self.lock_file_name += ".lock"
        self.locked = False
        self.lock = None
        self.lock_file = None
        self.blocking = blocking
        if not lock_folder:
            lock_folder = FileLock.DEFAULT_FILE_LOCK_PATH
        else:
            if not lock_folder.endswith("/"):
                lock_folder += "/"
        self.file_path = lock_folder + self.lock_file_name
        self._get_lock_file_handle()

    def __enter__(self):
        self.acquire()

    def __exit__(self, _type, value, traceback):
        self.release()

    def _get_lock_file_handle(self):
        self.lock_file = open(self.file_path, "w")

    def acquire(self, blocking=None):
        # Give an opportunity to set blocking with the class for context use
        if blocking is None:
            blocking = self.blocking

        if blocking:
            lock_mode = fcntl.LOCK_EX
        else:
            lock_mode = fcntl.LOCK_EX | fcntl.LOCK_NB
        if self.lock_file.closed:
            self._get_lock_file_handle()
        if not self.locked:
            try:
                self.lock = fcntl.flock(self.lock_file, lock_mode)
                self.locked = True
            except IOError:
                raise IOError("File '{}' is already locked.".format(self.lock_file_name))
        else:
            raise IOError("File '{}' is already locked.".format(self.lock_file_name))

    def release(self):
        if self.locked:
            try:
                self.lock_file.close()
                os.remove(self.file_path)
                self.locked = False
            except OSError:
                pass


class SessionTokenFileLock:

    TOKEN_TIMEOUT = 60 * 5

    def __init__(self, file_prefix, token_timeout=TOKEN_TIMEOUT):
        self.locked = False
        self.lock = None
        self.lock_file = None
        self.token_timeout = token_timeout
        self.file_path = "/var/run/ps/{}_token.lock".format(file_prefix)
        self.token_file_path = "/var/run/ps/{}_token".format(file_prefix)
        self._get_lock_file_handle()

    def __enter__(self):
        self.acquire()

    def __exit__(self, _type, value, traceback):
        self.release()

    def _get_lock_file_handle(self):
        self.lock_file = open(self.file_path, "w")

    def acquire(self):
        if self.lock_file.closed:
            self._get_lock_file_handle()
        if not self.locked:
            try:
                self.lock = fcntl.flock(self.lock_file, fcntl.LOCK_EX)
                self.locked = True
            except IOError:
                raise IOError("Session token file '{}' is already locked.".format(self.file_path))
        else:
            raise IOError("Session token file '{}' is already locked.".format(self.file_path))

    def release(self):
        if self.locked:
            try:
                self.lock_file.close()
                os.remove(self.file_path)
                self.locked = False
            except OSError:
                pass

    def get_token(self):
        token = ""
        try:
            if (int(time.time()) - os.path.getmtime(self.token_file_path)) > self.token_timeout:
                return token
        except IOError:
            return token
        try:
            with open(self.token_file_path) as f:
                f.seek(0)
                token = f.read()
        except IOError:
            pass
        return token

    def set_token(self, token):
        with open(self.token_file_path, "w") as f:
            f.write(token)


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
     :param str host: ip of remote host
     :param str username:
     :param str password:
     :param str keyfile: path to local public key file
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
            ssh_client.connect(host, username=username, password=password, look_for_keys=False)
        else:
            ssh_client.close()
            raise ValueError('Either password or keyfile must be passed to get_ssh_client.')
    except paramiko.ssh_exception.AuthenticationException:
        ssh_client.close()
        raise PermissionError('Incorrect credentials for host {}'.format(host))
    except (paramiko.ssh_exception.SSHException, socket_error) as ex:
        ssh_client.close()
        raise ConnectionRefusedError('Could not connect to host {}, error:\n{}'.format(host, str(ex)))
    logger.info('Successfully connected to {}'.format(host))
    return ssh_client


def transfer_file_sftp(ssh_client, local_path, remote_path, callback=None):
    """
     :param ssh_client:
     :type: paramiko.SSHClient
     :param local_path:
     :type: str
     :param remote_path:
     :type: str
     :param callback:
     :type: callable that accepts 2 arguments, bytes_transferred and total_bytes
    """
    logger.info("Transferring file '{}' to remote path {}.".format(local_path, remote_path))
    sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
    sftp_client.put(local_path, remote_path, callback=callback)
    logger.info("Done transferring file '{}' to remote path {}.".format(local_path, remote_path))


def get_file_sftp(ssh_client, local_path, remote_path):
    """Download file from remote server by SFTP
    :param ssh_client: SSH client object by generating from the get_ssh_client()
    :param local_path: Full path of the local file
    :param remote_path: Full path of the remote file
    :return: None
    """
    logger.info("Getting file '{}' and saving to '{}'".format(remote_path, local_path))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
    sftp_client.get(remote_path, local_path)
