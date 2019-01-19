from util.phantomjs_webkit import PhantomJSWebkit
from steps import OwaspStepBase


# Testing for Vulnerable Remember Password (OTG_AUTHN_005)
class OTG_AUTHN_005(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_AUTHN_005",
                                            description='Testing for Vulnerable Remember Password')

    # OTG_AUTHN_005
    def process_task(self, analysis_info):
        # Check
        pass_type_not_found = False
        content = ''
        if analysis_info.get_login_page():
            # Get login FORM
            content = PhantomJSWebkit.get_full_html(analysis_info.get_login_page())
            if content:
                try:
                    position = content.index('type="password"')
                    begin_position = position
                    while not content[begin_position:position].startswith('<input'):
                        begin_position -= 1
                    end_position = position + len('type="password"')
                    while not (content[begin_position:end_position].endswith('/>') or \
                               content[begin_position:end_position].endswith('>')):
                        end_position += 1
                except ValueError:
                    pass_type_not_found = True

        if not pass_type_not_found and content and 'autocomplete="off"' not in content[begin_position:end_position]:
            msg = 'The AUTOCOMPLETE attribute is not disabled on an HTML FORM/INPUT element containing password ' \
                  'type input.'
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_AUTHN_005.get_interface().title,
                                        description=OTG_AUTHN_005.get_interface().description,
                                        msg=msg, status=status)
