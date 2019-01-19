import time
import os
from selenium import webdriver


# PhantomJS Webkit class
class PhantomJSWebkit:

    # Private attributes
    _driver = webdriver.PhantomJS(executable_path=r'bin/phantomjs',
                                  service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'],
                                  service_log_path=os.devnull)
    _driver.set_window_size(1120, 550)

    # -- Static methods
    @staticmethod
    def get_full_html(url):
        PhantomJSWebkit._driver.get(url)
        time.sleep(3)
        return PhantomJSWebkit._driver.page_source
