import re
import json
from urlparse import urlparse
from steps import OwaspStepBase
from info.analysis import Analysis
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin
from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv11ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin
from sslyze.plugins.compression_plugin import CompressionPlugin
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.certificate_info_plugin import HostnameValidationResultEnum


# Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG_CRYPST_001)
class OTG_CRYPST_001(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CRYPST_001",
                                            description='Testing for Weak SSL/TLS Ciphers, Insufficient Transport '
                                                        'Layer Protection')

    # OTG_CRYPST_001
    def process_task(self, analysis_info):
        # Init
        target_info = OTG_CRYPST_001.__get_info_from_target_url(analysis_info.get_target())
        vulnerabilities = []
        if not target_info['https']:
            vulnerabilities.append('The target is not using HTTPS')
        else:
            server_info = ServerConnectivityInfo(hostname=target_info['server'], port=target_info['port'])
            server_info.test_connectivity_to_server()

            # -- Check

            # Checks heartbleed (CVE-2014-0160)
            plugin = HeartbleedPlugin()
            heartbleed_vulnerability = plugin.process_task(server_info, 'heartbleed').is_vulnerable_to_heartbleed
            if heartbleed_vulnerability:
                vulnerabilities.append('Heartbleed vulnerability (CVE-2014-0160)')

            # Checks OpenSSL CCS injection vulnerability (CVE-2014-0224)
            plugin = OpenSslCcsInjectionPlugin()
            css_injection_vulnerability = plugin.process_task(server_info, 'openssl_ccs').is_vulnerable_to_ccs_injection
            if css_injection_vulnerability:
                vulnerabilities.append('OpenSSL CCS injection vulnerability (CVE-2014-0224)')

            # LOGJAM vulnerability (CVE-2015-4000)
            plugin = OpenSslCipherSuitesPlugin()
            ciphersuites_result = plugin.process_task(server_info, Tlsv10ScanCommand())
            re_dhe = re.compile('[A-Z]*_DHE_[A-Z]*_EXPORT')
            accepted_cipher_name_list = [cipher.name for cipher in ciphersuites_result.accepted_cipher_list]
            logjam_vulnerability = False
            if not len(re_dhe.findall((",").join(accepted_cipher_name_list))) == 0:
                logjam_vulnerability = True
            try:
                if ciphersuites_result.preferred_cipher and \
                not ciphersuites_result.preferred_cipher.dh_info['GroupSize'] >= 2048:
                    logjam_vulnerability = True
            except Exception:
                logjam_vulnerability = True

            if logjam_vulnerability:
                vulnerabilities.append('LOGJAM vulnerability (CVE-2015-4000)')

            # CRIME (CVE-2012-4929) & BREACH (CVE-2013-3587)
            plugin = CompressionPlugin()
            compression_name_result = plugin.process_task(server_info, 'compression').compression_name
            if compression_name_result is not None:
                vulnerabilities.append('CRIME (CVE-2012-4929) & BREACH (CVE-2013-3587)')

            #  SSL client renogotaiation
            plugin = SessionRenegotiationPlugin()
            reneg_result = plugin.process_task(server_info, 'reneg')
            if reneg_result.accepts_client_renegotiation:
                vulnerabilities.append('SSL client renogotaiation supported')

            # POODLE (CVE-2014-3566), BEAST (CVE-2011-3389) and weak SSL protocols
            weak_protocols = []
            for protocol in [Sslv20ScanCommand(), Sslv30ScanCommand(), Tlsv10ScanCommand()]:
                plugin = OpenSslCipherSuitesPlugin()
                plugin_result = plugin.process_task(server_info, protocol)
                if len(plugin_result.accepted_cipher_list) > 0:
                    weak_protocols.append(protocol.get_cli_argument())
            if len(weak_protocols) > 0:
                vulnerabilities.append('POODLE (CVE-2014-3566), BEAST (CVE-2011-3389) and weak SSL protocols ' +
                                       str(json.dumps(weak_protocols)))

            # Minimum cipher strength requirements (>= 128 bits) not satisfied
            weak_ciphers = set()
            for protocol in [Tlsv11ScanCommand(), Tlsv12ScanCommand()]:
                plugin = OpenSslCipherSuitesPlugin()
                plugin_result = plugin.process_task(server_info, protocol)
                accepted_cipher_key_dict = {cipher.name: cipher.key_size for cipher in plugin_result.accepted_cipher_list}
                for cipher in accepted_cipher_key_dict:
                    if accepted_cipher_key_dict[cipher] < 128:
                        weak_ciphers.add(cipher)
            if len(weak_ciphers) > 0:
                vulnerabilities.append('Minimum cipher strength requirements (>= 128 bits) not satisfied ' +
                                       str(list(weak_ciphers)))

            # SSL/TLS perfect cipher suites
            not_perfect_ciphers = set()
            for protocol in [Tlsv11ScanCommand(), Tlsv12ScanCommand()]:
                plugin = OpenSslCipherSuitesPlugin()
                plugin_result = plugin.process_task(server_info, protocol)
                accepted_cipher_key_arr = [cipher.name for cipher in plugin_result.accepted_cipher_list]
                for accepted_cipher_key in accepted_cipher_key_arr:
                    if accepted_cipher_key not in not_perfect_ciphers and \
                                    accepted_cipher_key not in Analysis.PERFECT_CIPHER_SUITES:
                        not_perfect_ciphers.add(accepted_cipher_key)
            if len(not_perfect_ciphers) > 0:
                vulnerabilities.append('SSL/TLS perfect cipher suites not satisfied ' +
                                       str(list(not_perfect_ciphers)))

            # Certificate key is > 1024 bits
            plugin = CertificateInfoPlugin()
            plugin_certificate_result = plugin.process_task(server_info, CertificateInfoScanCommand())
            key_size = plugin_certificate_result.certificate_chain[0].as_dict['subjectPublicKeyInfo']['publicKeySize']
            if int(key_size) <= 1024:
                vulnerabilities.append('Certificate key is <= 1024 bits')

            # X509 Hostname validation
            plugin = CertificateInfoPlugin()
            plugin_certificate_result = plugin.process_task(server_info, CertificateInfoScanCommand())
            if plugin_certificate_result.hostname_validation_result is HostnameValidationResultEnum.NAME_DOES_NOT_MATCH:
                vulnerabilities.append('X509 Hostname validation failed')

            # Check wildcard certificates
            plugin = CertificateInfoPlugin()
            plugin_certificate_result = plugin.process_task(server_info, CertificateInfoScanCommand())
            # Common Name
            cn = plugin_certificate_result.certificate_chain[0].as_dict['subject']['commonName']
            if '*' in cn:
                vulnerabilities.append('Wildcards are not allowed in CN')
            # Subject Alternative Name
            try:
                san_list = plugin_certificate_result.certificate_chain[0].as_dict['extensions']\
                                                                             ['X509v3 Subject Alternative Name']['DNS']
                san_with_asterisk = [san for san in san_list if '*' in san]
                if len(san_with_asterisk) > 0:
                    vulnerabilities.append('Wildcards are not allowed in SAN')
            except KeyError:
                # Nothing to do because X509v3 Subject Alternative Name not found
                pass

            # Check SAN with IP address
            plugin = CertificateInfoPlugin()
            plugin_certificate_result = plugin.process_task(server_info, CertificateInfoScanCommand())
            # Subject Alternative Name
            try:
                san_list = plugin_certificate_result.certificate_chain[0].as_dict['extensions']\
                                                                                 ['X509v3 Subject Alternative Name']['IP']
                ip_match_list = [ip for ip in san_list if OTG_CRYPST_001.__isIPv4(ip)]
                if len(ip_match_list) > 0:
                    vulnerabilities.append('IPs are not allowed in SAN')
            except KeyError:
                # Nothing to do because X509v3 Subject Alternative Name not found
                pass

        # Prepare output
        if len(vulnerabilities) > 0:
            msg = str(vulnerabilities)
            status = OwaspStepBase.status.error.value
        else:
            msg = 'Passed.'
            status = OwaspStepBase.status.passed.value

        # Return
        return OwaspStepBase.StepResult(title=OTG_CRYPST_001.get_interface().title,
                                        description=OTG_CRYPST_001.get_interface().description,
                                        msg=msg, status=status)

    # Private methods

    @staticmethod
    def __isIPv4(string_ip):
        pieces = string_ip.split('.')
        if len(pieces) != 4: return False
        try:
            return all(0 <= int(p) < 256 for p in pieces)
        except ValueError:
            return False

    @staticmethod
    def __get_info_from_target_url(target):
        parsed_uri = urlparse(target)
        scheme = '{uri.scheme}'.format(uri=parsed_uri)
        if 'https' not in scheme:
            return {'https': False}
        else:
            net_location = '{uri.netloc}'.format(uri=parsed_uri)
            if ':' not in net_location:
                return {'https': True, 'server': net_location, 'port': 443}
            else:
                splitted_location = net_location.split(':')
                return {'https': True, 'server': splitted_location[0], 'port': int(splitted_location[1])}
