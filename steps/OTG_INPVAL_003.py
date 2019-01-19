import requests
from steps import OwaspStepBase
from info.analysis import Analysis


# Testing for HTTP Verb Tampering (OTG_INPVAL_003)
class OTG_INPVAL_003(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_INPVAL_003",
                                            description='Testing for HTTP Verb Tampering')

    # OTG_INPVAL_003
    def process_task(self, analysis_info):
        responses = {}
        for method in Analysis.HTTP_METHODS:
            try:
                requests.packages.urllib3.disable_warnings()
                responses[method] = requests.request(method, analysis_info.get_target(), timeout=5, verify=False)

            except requests.exceptions.ReadTimeout:
                responses[method] = 'Read timed out'

        # Check
        otg_inpval_003_passed = True
        msg = ''
        if responses['GET'].status_code == responses['PROPFIND'].status_code or \
                        responses['GET'].status_code == responses['FAKE'].status_code:
            msg = 'Arbitrary HTTP Verbs accepted.'
            status = OwaspStepBase.status.error.value
            otg_inpval_003_passed = False

        if responses['GET'].status_code != responses['HEAD'].status_code and \
                        responses['HEAD'].status_code not in [405, 501]:
            if msg:
                msg += ' '
            msg += 'HEAD HTTP Verb does not produce the same results.'
            status = OwaspStepBase.status.error.value
            otg_inpval_003_passed = False

        if otg_inpval_003_passed:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_INPVAL_003.get_interface().title,
                                        description=OTG_INPVAL_003.get_interface().description,
                                        msg=msg, status=status)
