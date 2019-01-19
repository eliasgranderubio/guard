import requests
from steps import OwaspStepBase


# Testing for Clickjacking (OTG_CLIENT_009)
class OTG_CLIENT_009(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CLIENT_009", description='Testing for Clickjacking')

    # OTG_CLIENT_009
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        response = requests.request('GET', analysis_info.get_target(), timeout=5, verify=False)

        # Check
        if response.headers.get('X-FRAME-OPTIONS') is None:
            msg = 'X-FRAME-OPTIONS header not set.'
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CLIENT_009.get_interface().title,
                                        description=OTG_CLIENT_009.get_interface().description,
                                        msg=msg, status=status)
