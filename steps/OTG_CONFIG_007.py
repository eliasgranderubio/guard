import requests
from steps import OwaspStepBase


# Test HTTP Strict Transport Security (OTG_CONFIG_007)
class OTG_CONFIG_007(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CONFIG_007", description='Test HTTP Strict Transport Security')

    # OTG_CONFIG_007
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        response = requests.request('GET', analysis_info.get_target(), timeout=5, verify=False)

        # Check
        if response.headers.get('Strict-Transport-Security') is None:
            msg = 'HSTS header not set.'
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CONFIG_007.get_interface().title,
                                        description=OTG_CONFIG_007.get_interface().description,
                                        msg=msg, status=status)



