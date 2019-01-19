import logging
import sys


# Logger class

class Logger(logging.Logger):

    # -- Init
    logging.basicConfig(format='%(message)s', stream=sys.stdout)
    _logger_name = 'Logger'
    _logger = None

    # -- Private attributes

    _OKGREEN = '\033[92m'
    _WARNING = '\033[93m'
    _FAIL = '\033[91m'
    _BOLD = '\033[1m'
    _ENDC = '\033[0m'

    # -- Public methods

    def info(self, msg, bold=False):
        if bold:
            logging.warning(Logger._BOLD + msg + Logger._ENDC)
        else:
            logging.warning(msg)

    def passed(self, msg):
        logging.warning(Logger._OKGREEN + msg + Logger._ENDC)

    def warn(self, msg):
        logging.warning(Logger._WARNING + msg + Logger._ENDC)

    def error(self, msg):
        logging.error(Logger._FAIL + msg + Logger._ENDC)

    # -- Static methods

    @staticmethod
    def get_logger():
        if Logger._logger is None:
            Logger._logger = Logger(Logger._logger_name)
        return Logger._logger
