import requests
from steps import OwaspStepBase
from info.analysis import Analysis


# Test HTTP Methods (OTG_CONFIG_006)
class OTG_CONFIG_006(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CONFIG_006", description='Test HTTP Methods')


    # OTG_CONFIG_006
    def process_task(self, analysis_info):
        responses = {}
        for method in Analysis.HTTP_METHODS:
            try:
                requests.packages.urllib3.disable_warnings()
                responses[method] = requests.request(method, analysis_info.get_target(), timeout=5, verify=False)

            except requests.exceptions.ReadTimeout:
                responses[method] = 'Read timed out'

        # Check
        potencially_security_risk_http_methods = []
        for method in Analysis.HTTP_METHODS:
            if 'Read timed out' not in responses[method]:
                if responses[method].status_code not in [405, 501]:
                    if method in Analysis.POTENCIALLY_SECURITY_RISK_HTTP_METHODS:
                        potencially_security_risk_http_methods.append(method)

        if len(potencially_security_risk_http_methods) > 0:
            msg = str(potencially_security_risk_http_methods)
            status = OwaspStepBase.status.warning.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CONFIG_006.get_interface().title,
                                        description=OTG_CONFIG_006.get_interface().description,
                                        msg=msg, status=status)
