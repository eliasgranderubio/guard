from log.logger import Logger
from steps import OwaspStepBase


# Text printer class
class TextPrinter:

    # Constants
    _OWASP_STEP_GROUPS = ['OTG_INFO', 'OTG_CONFIG', 'OTG_AUTHN', 'OTG_SESS', 'OTG_INPVAL', 'OTG_CRYPST',
                          'OTG_BUSLOGIC', 'OTG_CLIENT']
    _OWASP_STEP_GROUPS_DESC = ['Information Gathering',
                               'Configuration and Deployment Management Testing',
                               'Authentication Testing',
                               'Session Management Testing',
                               'Input Validation Testing',
                               'Testing for weak Cryptography',
                               'Business Logic Testing',
                               'Client Side Testing']

    # -- Public methods

    # Constructor
    def __init__(self, steps_output):
        self._steps_output = steps_output
        self._ordered_steps = {}
        for group in TextPrinter._OWASP_STEP_GROUPS:
            self._ordered_steps[group] = []

    # Generate report
    def generate_report(self):
        if self._steps_output is not None:
            for step_output in self._steps_output:
                self._ordered_steps[step_output.get_title()[:step_output.get_title().index('_', 4)]]\
                    .append(step_output)

        count = 0
        for group in TextPrinter._OWASP_STEP_GROUPS:
            Logger.get_logger().info('\n[{0}] {1}'.format(group, TextPrinter._OWASP_STEP_GROUPS_DESC[count]),
                                     bold=True)
            self._ordered_steps[group].sort(key=lambda x: x.get_title(), reverse=False)
            for step_output in self._ordered_steps[group]:
                output_msg = '[{0}] {1}: {2}'.format(step_output.get_title(),
                                                     step_output.get_description(),
                                                     step_output.get_msg())
                if step_output.get_status() == OwaspStepBase.status.error.value:
                    Logger.get_logger().error(output_msg)
                elif step_output.get_status() == OwaspStepBase.status.warning.value:
                    Logger.get_logger().warn(output_msg)
                elif step_output.get_status() == OwaspStepBase.status.passed.value:
                    Logger.get_logger().passed(output_msg)
                elif step_output.get_status() == OwaspStepBase.status.info.value:
                    Logger.get_logger().info(output_msg)
            count += 1
