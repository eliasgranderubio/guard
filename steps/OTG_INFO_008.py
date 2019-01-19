import json
from steps import OwaspStepBase
from util.wappalyzer import Wappalyzer


# Fingerprint Web Application Framework (OTG_INFO_008)
class OTG_INFO_008(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_INFO_008", description='Fingerprint Web Application Framework')

    # OTG_INFO_008
    def process_task(self, analysis_info):
        # Get frameworks results
        frameworks = Wappalyzer().run(analysis_info.get_target())

        # Check
        if json.loads('{}') == frameworks or json.loads('{"applications": []}') == frameworks:
            msg = 'No frameworks found.'
            status = OwaspStepBase.status.passed.value
        else:
            msg = 'Passed.\n'
            msg += json.dumps(frameworks, indent=4, sort_keys=True) + '\n'
            status = OwaspStepBase.status.error.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_INFO_008.get_interface().title,
                                        description=OTG_INFO_008.get_interface().description,
                                        msg=msg, status=status)
