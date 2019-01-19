import os
import sys
import traceback
from info.analysis import Analysis
from steps import OwaspStepsFinder
from util.text_printer import TextPrinter
from util.cli_parser import CLIParser


def kill_phantomjs():
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            cmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').readline()
            if 'bin/phantomjs' in cmd:
                os.kill(int(pid), 9)
        except IOError:  # proc has already terminated
            continue


def main(parsed_args):
    # -- Init
    analysis_info = Analysis(input_file=parsed_args.get_app_info())

    # -- OWASP steps initialization
    owasp_steps = OwaspStepsFinder()
    available_steps = owasp_steps.get_steps()

    try:
        # -- OWASP steps
        steps_outputs = []
        for step in available_steps:
            step_output = step().process_task(analysis_info=analysis_info)
            steps_outputs.append(step_output)

        # -- OWASP show results
        TextPrinter(steps_output=steps_outputs).generate_report()
    except:
        traceback.print_exc(file=sys.stderr)

    # -- Clean up
    kill_phantomjs()


if __name__ == "__main__":
    main(CLIParser())
