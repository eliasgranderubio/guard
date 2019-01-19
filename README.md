# Guard


Guard is a project which allows you run OWASP framework in an automate way. It integrates other tools like [Nmap](https://nmap.org/), [Wappalyzer](https://wappalyzer.com/) and [PhantomJS](http://phantomjs.org/) for fulfilling its mission.


## Requirements
Before **Guard** usage, you must have installed the next requirements:

* Python 2.7
* Docker
* Nmap
* Pip
  * Docker
  * Selenium
  * SSLyze
  * Python-nmap


The requirements can be installed with pip:
```
    sudo python2 -m pip install -r requirements.txt
```

### Installation of Docker

If you need instructions for Docker installation, see the [How-to install Docker](https://docs.docker.com/install/) page.

In order to avoid having to use `sudo` when you use the `docker` command, create a Unix group called `docker` and add users to it. When the `docker` daemon starts, it makes the ownership of the Unix socket read/writable by the `docker` group.


## Integrated tools

* [PhantomJS](http://phantomjs.org/) - Allows web scraping in all web pages, whatever it is the web page technology has: HTML5 only or Single Page Apps with AngularJS or others. 
* [Nmap](https://nmap.org/) - At the moment, Nmap is only used for enumerating applications on webserver.
* [Wappalyzer](https://wappalyzer.com/) - Cross-platform utility that uncovers the technologies used on websites. It detects content management systems, ecommerce platforms, web frameworks, server software, analytics tools and many more.

## Project overview


### Project structure

**Guard** project has the next structure:

* guard (Main folder)
  * bin (Contains the PhantomJS binary)
  * info (Contains the analysis class which it will have the input info parsed and other info about the current analysis)
  * log (Contains the logger class for printing information in the stdout/stderr)
  * steps (Contains all the OWASPv4 implemented steps)
  * util (Utilities adapted for this project like PhantomJS adapter and others)
  * guard.py (Python script which contains the entry point)


### Project implementation details

**Guard** project has been developed using POO with Python 2.7 and Python introspection.

The first step was define an OWASP step base class as parent class in the hierarchy. Below, the base class defined is shown:
```
# -- OWASP Step base
class OwaspStepBase(object):

    # Base OWASP Step abstract class. All steps have to inherit from it.
    __metaclass__ = abc.ABCMeta

    # Class method
    @classmethod
    def get_interface(step_class):
        return step_class.interface

    # Abstract method
    @abc.abstractmethod
    def process_task(self, analysis_info):
        return
```

If you want develop an OWASP step, your new Python class must extends the previous base class and implement the function `process_task`. Below, the beginning of the **Testing for Clickjacking (OTG_CLIENT_009)** OWASP step is shown for ilustrative purposes:

```
# Testing for Clickjacking (OTG_CLIENT_009)
class OTG_CLIENT_009(OwaspStepBase.OwaspStepBase):

    interface = OwaspStepBase.StepInterface(title="OTG_CLIENT_009", description='Testing for Clickjacking')

    # OTG_CLIENT_009
    def process_task(self, analysis_info):
    	... # Implementation of the step
```


Finally, thanks to class introspection and the class hierarchy defined, the main function looks quite simple. Below, the main fuction is shown: 
```
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
```

## Usage

### Whole project usage

If you want use the whole project with all OWASP steps implemented, you must run the next command:
```
    python guard.py -i input.json
```

An example of `input.json` file content is shown below:

```
    {
      "target": "https://www.example.org/",
      "login_page": "https://www.example.org/login"
    }
```

### Running a specific OWASP step

At the moment, for running a specific OWASP step, it is necessary create a little script and run it from the same directory which `guard.py` is, because phantomJS is not installed in `/usr/bin` and it is loaded from a relative path. Below, a script example is shown:


```
    from info.analysis import Analysis
    
    # Create custom analysis
    analysis = Analysis()
    analysis.set_target('https://www.example.org/')
    
    # Run OWASP step
    result = OTG_CRYPST_001().process_task(analysis)
    
    # Print results
    print('Title:       ' + result.get_title())
    print('Description: ' + result.get_description())
    print('Status:      ' + result.get_status())
    print('Message:     ' + result.get_msg())
```