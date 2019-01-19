import requests
import json
from steps import OwaspStepBase
from info.analysis import Analysis


# Test Cross Origin Resource Sharing (OTG_CLIENT_007)
#######################################################################################################################
# TODO review if it is necessary check CORS settings attributes
#      https://developer.mozilla.org/en-US/docs/Web/HTML/CORS_settings_attributes
#
# The HTML specification introduces a crossorigin attribute that, in combination with an appropriate CORS header,
# allows:
#
# For img:
#    The crossorigin attribute is a CORS settings attribute. Its purpose is to allow images from third-party
#    sites that allow cross-origin access to be used with canvas.
#
# For script:
#    The crossorigin attribute is a CORS settings attribute. It controls, for scripts that are obtained from other
#    origins, whether error information will be exposed.
#
#######################################################################################################################
class OTG_CLIENT_007(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CLIENT_007", description='Test Cross Origin Resource Sharing')

    # OTG_CLIENT_007
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        cors_wildcard_arr = []
        cors_methods_arr = []
        url = analysis_info.get_target()

        response = requests.request('GET', url, timeout=5, verify=False)

        # Get CORS header
        cors_methods = ''
        if response.headers.get('Access-Control-Allow-Origin') is not None and \
            response.headers.get('Access-Control-Allow-Origin') == '*':
            cors_wildcard_arr.append(url)
        if response.headers.get('Access-Control-Allow-Methods'):
            cors_methods = response.headers.get('Access-Control-Allow-Methods')

        potencially_security_risk_cors_methods = []
        for method in Analysis.POTENCIALLY_SECURITY_RISK_HTTP_METHODS:
            if method in cors_methods:
                potencially_security_risk_cors_methods.append(method)
        if len(potencially_security_risk_cors_methods) > 0:
            cors_methods_arr.append('HTTP Methods in URL {' + url + '}: ' +
                                    str(potencially_security_risk_cors_methods))

        # Check
        msg = ''
        if len(cors_methods_arr) > 0:
            msg = str(json.dumps(cors_methods_arr))
            status = OwaspStepBase.status.warning.value
        if len(cors_wildcard_arr) > 0:
            if msg:
                msg += ', '
            msg += 'Insecure response with wildcard "*" in Access-Control-Allow-Origin ' + \
                   str(json.dumps(cors_wildcard_arr)) + '.'
            status = OwaspStepBase.status.error.value
        if len(cors_wildcard_arr) == 0 and len(potencially_security_risk_cors_methods) == 0:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CLIENT_007.get_interface().title,
                                        description=OTG_CLIENT_007.get_interface().description,
                                        msg=msg, status=status)
