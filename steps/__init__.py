import os
import sys
import inspect
from imp import load_module, find_module
import steps.OwaspStepBase


# OWASP Steps finder
class OwaspStepsFinder:

    # -- Public methods

    # Constructor
    def __init__(self):
        self.__step_classes = set([])

        steps_modules = self.__get_step_modules_dynamic()
        for module in steps_modules:
            for name in dir(module):
                obj = getattr(module, name)
                if name not in module.__name__:
                    continue

                if inspect.isclass(obj):
                    if obj != steps.OwaspStepBase.OwaspStepBase:
                        for base in obj.__bases__:
                            # H4ck because issubclass() doesn't seem to work as expected on Linux
                            # It has to do with OwaspStep being imported multiple times (within plugins) or something
                            if base.__name__ == 'OwaspStepBase':
                                # A step was found, keep it
                                self.__step_classes.add(obj)

    # -- Getters

    def get_steps(self):
        return self.__step_classes

    # -- Private methods

    # -- Static methods

    @staticmethod
    def __get_step_modules_dynamic():

        step_modules = []

        step_dir = steps.__path__[0]
        full_step_dir = os.path.join(sys.path[0], step_dir)

        if os.path.exists(full_step_dir):
            for (root, dirs, files) in os.walk(full_step_dir):
                del dirs[:]  # Do not walk into subfolders of the step directory
                # Checking every .py module in the step directory
                steps_loaded = []
                for source in (s for s in files if s.endswith((".py"))):
                    module_name = os.path.splitext(os.path.basename(source))[0]
                    if module_name in steps_loaded:
                        continue
                    steps_loaded.append(module_name)
                    full_name = os.path.splitext(source)[0].replace(os.path.sep, '.')

                    try:  # Try to import the step package
                        # The step package HAS to be imported as a submodule
                        # of module 'steps' or it will break windows compatibility
                        (file, pathname, description) = \
                            find_module(full_name, steps.__path__)
                        module = load_module('steps.' + full_name, file,
                                             pathname, description)
                    except Exception as e:
                        print('  ' + module_name + ' - Import Error: ' + str(e))
                        continue

                    step_modules.append(module)

        return step_modules
