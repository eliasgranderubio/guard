import docker
import json


# -- Wappalyzer

class Wappalyzer:

    # -- Public methods

    # Wappalyzer Constructor
    def __init__(self):
        self.cli = docker.from_env(version="auto", timeout=3600).api
        # docker pull barbudo/wappalyzer
        self.cli.pull('barbudo/wappalyzer', tag='latest')
        self.container_id = None

    # Run Wappalyzer
    def run(self, target):
        # docker run barbudo/wappalyzer <target>
        container = self.cli.create_container(image='barbudo/wappalyzer', command=target)
        container_id = container.get('Id')
        self.cli.start(container=container_id)
        logs = self.cli.logs(container=container_id, follow=True)
        if logs is not None:
            return json.loads(logs)
        return json.loads('{}')
