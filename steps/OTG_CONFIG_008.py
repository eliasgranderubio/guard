import requests
import json
from steps import OwaspStepBase


# Test RIA cross domain policy (OTG_CONFIG_008)
class OTG_CONFIG_008(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CONFIG_008", description='Test RIA cross domain policy')

    # Private info
    _cross_domain_policy_files = ['crossdomain.xml', 'clientaccesspolicy.xml']

    # OTG_CONFIG_008
    def process_task(self, analysis_info):
        # Init
        requests.packages.urllib3.disable_warnings()

        # Prepare URL base
        url_base = analysis_info.get_target()
        if not url_base.endswith('/'):
            url_base += '/'

        # Check
        warnings = []
        for cross_domain_policy_file in OTG_CONFIG_008._cross_domain_policy_files:
            response = requests.request('GET', url_base + cross_domain_policy_file, timeout=5, verify=False)
            if response.status_code == 200:
                content = response.content
                if 'domain="*"' in content:
                    warnings.append(cross_domain_policy_file)

        # Check
        if len(warnings) > 0:
            msg = 'Overly permissive policy with wildcard "*" in ' + str(json.dumps(warnings))
            status = OwaspStepBase.status.warning.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CONFIG_008.get_interface().title,
                                        description=OTG_CONFIG_008.get_interface().description,
                                        msg=msg, status=status)
