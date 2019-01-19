import abc
import enum


# -- OWASP Step Interface
class StepInterface:

    def __init__(self, title, description):
        self.title = title
        self.description = description


# -- Step result valid status
class status(enum.Enum):
    info = 'info'
    passed = 'passed'
    warning = 'warning'
    error = 'error'


# -- OWASP Step Result
class StepResult:

    # OWASPStep.process_task() should return an instance of this class
    def __init__(self, title, description, msg, status):
        self._title = title
        self._description = description
        self._msg = msg
        self._status = status

    def get_title(self):
        return self._title

    def get_description(self):
        return self._description

    def get_msg(self):
        return self._msg

    def get_status(self):
        return self._status


# -- OWASP Step base
class OwaspStepBase(object):

    # Base OWASP Step abstract class. All steps have to inherit from it.
    __metaclass__ = abc.ABCMeta

    # Class method
    @classmethod
    def get_interface(step_class):
        return step_class.interface

    # Abstract method
    @abc.abstractmethod
    def process_task(self, analysis_info):
        return
