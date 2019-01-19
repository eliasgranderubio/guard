import re
import requests
from steps import OwaspStepBase
from info.analysis import Analysis


# Fingerprint Web Server (OTG_INFO_002)
class OTG_INFO_002(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_INFO_002", description='Fingerprint Web Server')

    # OTG_INFO_002
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        response = requests.request('GET', analysis_info.get_target(), timeout=5, verify=False)

        # Get Server header
        fingerprint = response.headers.get('Server') if response.headers.get('Server') else ''

        # Check
        passed = True
        if fingerprint:
            for well_known_server in Analysis.WELL_KNONW_SERVERS:
                if well_known_server in fingerprint:
                    passed = False
            if passed and re.search("([0-9]+[\.[0-9]*]*)", fingerprint):
                passed = False

        if not passed:
            msg = fingerprint
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_INFO_002.get_interface().title,
                                        description=OTG_INFO_002.get_interface().description,
                                        msg=msg, status=status)
