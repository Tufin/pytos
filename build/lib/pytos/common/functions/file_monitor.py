
import threading
import pyinotify
import logging
import atexit
from abc import abstractmethod

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

logger = logging.getLogger(COMMON_LOGGER_NAME)


class ModifiedFileEventHandler(pyinotify.ProcessEvent):
    def my_init(self, callback=None):
        self._callback = callback

    def process_IN_CLOSE_WRITE(self, event):
        self._callback()

    def process_IN_MODIFY(self, event):
        self._callback()


class FileMonitor:
    FILE_CHANGE_MASK = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MODIFY

    def __init__(self, file_paths, watch_mask=FILE_CHANGE_MASK):
        self.inotify_watch_manager = pyinotify.WatchManager()
        self._file_paths = file_paths
        self._event_handler = ModifiedFileEventHandler(callback=self._reload_modified_file)
        self._inotify_notifier = pyinotify.Notifier(self.inotify_watch_manager, default_proc_fun=self._event_handler)
        self._loop_thread = threading.Thread(target=self._inotify_notifier.loop, daemon=True)
        for file_path in self._file_paths:
            self.inotify_watch_manager.add_watch(file_path, watch_mask)
        self._loop_thread.start()
        atexit.register(self._shutdown)

    def _shutdown(self):
        for watch in self.inotify_watch_manager.watches.copy():
            self.inotify_watch_manager.del_watch(watch)
        self._inotify_notifier.stop()
        self._loop_thread.join(0.1)

    def __del__(self):
        self._shutdown()

    @abstractmethod
    def _reload_modified_file(self, *args, **kwargs):
        raise NotImplementedError
