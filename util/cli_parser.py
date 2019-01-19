import argparse


# CLIParser class
class CLIParser:

    # -- Public methods

    # CLIParser Constructor
    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='guard.py', description='OWASP Guard')
        self.parser.add_argument('-i', '--app_info', required=True, type=argparse.FileType('r'),
                                 help='the input file with the application info')
        self.parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1.0',
                                 help='show the version message and exit')
        self.args, self.unknown = self.parser.parse_known_args()

    # -- Getters

    # Gets app_info
    def get_app_info(self):
        return self.args.app_info.name
