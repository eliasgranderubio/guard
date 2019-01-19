import nmap
from urlparse import urlparse
from steps import OwaspStepBase


# Enumerate Applications on Webserver (OTG_INFO_004)
class OTG_INFO_004(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_INFO_004", description='Enumerate Applications on Webserver')

    # OTG_INFO_004
    def process_task(self, analysis_info):
        # Init
        parsed = urlparse(analysis_info.get_target())
        hostname = parsed.netloc
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        # Check
        nm = nmap.PortScanner()
        nm.scan(hostname, '-')

        services = 'Passed.\n'
        for line in nm.csv().splitlines():
            splitted_lines = line.split(";")
            if "user" in splitted_lines[2]:
                services += splitted_lines[4] + '/' + splitted_lines[3] + "\t" + splitted_lines[6] + "\t" + \
                            splitted_lines[5] + "\t" + splitted_lines[7] + " " + splitted_lines[8] + " " + \
                            splitted_lines[10] + " " + splitted_lines[12] + "\n"

        # Prepare output
        msg = services
        status = OwaspStepBase.status.warning.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_INFO_004.get_interface().title,
                                        description=OTG_INFO_004.get_interface().description,
                                        msg=msg, status=status)
