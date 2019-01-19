import re
import requests
from datetime import date
from steps import OwaspStepBase


# Testing for Browser cache weakness (OTG_AUTHN_006)
class OTG_AUTHN_006(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_AUTHN_006",
                                            description='Testing for Browser cache weakness')


    # OTG_AUTHN_006
    def process_task(self, analysis_info):
        requests.packages.urllib3.disable_warnings()
        response = requests.request('GET', analysis_info.get_target(), timeout=5, verify=False)

        # Get Browser cache headers
        cache_control = ''
        pragma = ''
        expires = ''
        if response.headers.get('Pragma') is not None:
            pragma = response.headers.get('Pragma')
        if response.headers.get('Cache-Control') is not None:
            cache_control = response.headers.get('Cache-Control')
        if response.headers.get('Expires') is not None:
            expires = response.headers.get('Expires')

        # Check
        browser_cache_weakness = []
        if not pragma or 'no-cache' not in pragma:
            browser_cache_weakness.append('Pragma: no-cache')
        if not expires or ('0' != expires and not \
                (re.search("([0-9]{4})", expires) is not None and
                         int(re.search("([0-9]{4})", expires).group(0)) < date.today().year)):
            browser_cache_weakness.append('Expires: 0')
        if not cache_control or 'no-cache' not in cache_control or  'no-store' not in cache_control:
            browser_cache_weakness.append('Cache-Control: no-cache, no-store')

        if len(browser_cache_weakness) > 0:
            msg = 'The next headers are not set: ' + str(browser_cache_weakness)
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_AUTHN_006.get_interface().title,
                                        description=OTG_AUTHN_006.get_interface().description,
                                        msg=msg, status=status)
