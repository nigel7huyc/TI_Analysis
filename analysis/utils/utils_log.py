import os
import logging

from logging import StreamHandler
from logging.handlers import RotatingFileHandler

from settings import *
from utils.utils_conf import LogConfigReader


class LogFactory(object):

    @classmethod
    def add_handler(cls, input_logger, input_handler, input_format, input_level):
        input_handler.setFormatter(input_format)
        input_handler.setLevel(input_level)
        input_logger.addHandler(input_handler)
        return input_logger

    @classmethod
    def get_log(cls, logfile, max_bytes=10*1024*1024, backup_count=5):
        """
        :param logfile: The Log Tag Name in SysConfig.ini
        :param max_bytes: The maximum bytes of single logfile
        :param backup_count: The number of backup logfile
        :return: The instance of file logger
        """
        logger = logging.getLogger(logfile)
        log_configure = LogConfigReader()
        log_level = log_configure.get_log_level()

        if not logger.handlers:
            log_filename = log_configure.get_log_path(logfile)

            file_handler = RotatingFileHandler(log_filename, mode='a', maxBytes=max_bytes,
                                               backupCount=backup_count, encoding='utf-8')
            log_format = logging.Formatter(log_configure.get_log_format())
            logger = cls.add_handler(logger, file_handler, log_format, log_level)

        logger.setLevel(log_level)
        return logger

    @classmethod
    def get_stream_log(cls, logfile='CONSOLE_DEBUGGER'):
        """
        :param logfile: The Log Tag Name in SysConfig.ini
        :return: The instance of stream logger
        """
        logger = logging.getLogger(logfile)
        log_configure = LogConfigReader()
        log_level = log_configure.get_log_level()

        if not logger.handlers:
            file_handler = StreamHandler()
            log_format = logging.Formatter(log_configure.get_log_format())
            logger = cls.add_handler(logger, file_handler, log_format, log_level)

        logger.setLevel(log_level)
        return logger