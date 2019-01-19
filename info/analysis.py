import json


# Analysis info class

class Analysis:

    # -- Constants
    WELL_KNONW_SERVERS = ['Apache', 'Apache-Coyote', 'nginx', 'spray-can', 'openresty', 'TornadoServer', 'Jetty',
                          'Netty', 'Microsoft-IIS', 'Netscape-Enterprise', 'Sun-ONE-Web-Server', 'JBoss-EAP',
                          'WildFly', 'Oracle-HTTP-Server']
    HTTP_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PROPFIND', 'FAKE']
    POTENCIALLY_SECURITY_RISK_HTTP_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
    PERFECT_CIPHER_SUITES = ['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                             'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                             'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA256',
                             'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                             'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                             'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_RSA_WITH_AES_256_GCM_SHA384',
                             'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                             'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
                             'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                             'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                             'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256']

    # -- Public methods

    # Constructor
    def __init__(self, input_file=None):
        if input_file is not None:
            input_json = self.__read_input_file(input_file=input_file)
            self.target = self.__read_key_from_json(input_json, "target")
            self.login_page = self.__read_key_from_json(input_json, "login_page")
        else:
            self.target = ''
            self.login_page = ''

    # -- Getters and setters

    def get_target(self):
        return self.target

    def get_login_page(self):
        return self.login_page

    # -- Private methods

    # Read input file to JSON obj
    @staticmethod
    def __read_input_file(input_file):
        json_str = '{}'
        with open(input_file, 'rb') as f:
            lines = f.readlines()
            if len(lines) > 0:
                json_str = ''
                for line in lines:
                    json_str += line.decode('utf-8')
        return json.loads(json_str)

    # Read JSON key
    @staticmethod
    def __read_key_from_json(input_json, key, default_value=None):
        try:
            return input_json[key]
        except KeyError:
            if default_value is not None:
                return default_value
            else:
                return ''
