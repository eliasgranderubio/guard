import requests
from steps import OwaspStepBase


# Testing for Reflected Cross site scripting (OTG_INPVAL_001)
class OTG_INPVAL_001(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_INPVAL_001",
                                            description='Testing for Reflected Cross site scripting')

    # OTG_INPVAL_001
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        response = requests.request('GET', analysis_info.get_target(), timeout=5, verify=False)

        # Check
        if response.headers.get('X-XSS-Protection') is not None and '0' != response.headers.get('X-XSS-Protection'):
            msg = 'Passed (XSS-Protection enabled).'
            status = OwaspStepBase.status.passed.value
        else:
            msg = 'X-XSS-Protection header not set.'
            status = OwaspStepBase.status.error.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_INPVAL_001.get_interface().title,
                                        description=OTG_INPVAL_001.get_interface().description,
                                        msg=msg, status=status)