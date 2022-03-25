"""
    Gathers all the available monitors, imports them and exposes them to be instantiated
    by Telemetry classs
"""
import glob
import logging
from os.path import dirname, basename, isfile
from typing import Dict

modules = glob.glob(dirname(__file__) + "/*.py")


class Monitors:
    """
    Wrapper class for available monitors

        monitors: Currently registered and imported monitors
    """
    monitors: Dict = {}

    @classmethod
    def get_monitor(cls, monitor_name: str):
        """
        Returns a monitor class provided a name
        Args:
            monitor_name: monitor to retreive

        Returns:

        """
        return cls.monitors.get(monitor_name)

    @classmethod
    def register_monitor(cls, monitor_name: str, p_monitor):
        """
        Registers a new monitor module provided a name and the module
        Args:
            monitor_name: Monitor name to be registered
            p_monitor: Monitor module to be registered
        """
        logging.getLogger().setLevel(logging.INFO)
        logging.info(f'Distribution {monitor_name} registered')
        cls.monitors[monitor_name] = p_monitor

    @classmethod
    def monitor(cls, monitor_name: str = None):
        """
        Tries to register the monitor name provided by name
        Args:
            monitor_name: monitor to be created and registered

        Returns: Monitor class

        """
        def decorator(monitor_class):
            _monitor_name: str = monitor_name
            if not monitor_name:
                _monitor_name = monitor_class.__name__

            if _monitor_name in cls.monitors:
                logging.error(f'Monitor {_monitor_name} is already defined')
            else:
                cls.register_monitor(_monitor_name, monitor_class)

            return monitor_class
        return decorator


monitor = Monitors.monitor
get_monitor = Monitors.get_monitor
register_monitor = Monitors.register_monitor
monitors = Monitors.monitors

for m in modules:
    if isfile(m) and not m.endswith('__init__.py'):
        __all__ = [basename(m)[:-3]]
        try:
            from . import *
        except ModuleNotFoundError:
            logging.exception(f'Module {__all__[0]} not fount')
