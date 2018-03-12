from rule_chains.frontend import GrokFrontend
from rule_chains import get_names, get_patterns, get_grokit_config

DEFAULT_NAMES = get_names()
DEFAULT_PATTERNS = get_patterns()
GROK_FE = None
DEFAULT_CONFIG = get_grokit_config()


class GrokInterface(object):

    def __init__(self):
        self.gfe = self.build_grok_etl()

    @classmethod
    def build_grok_etl(cls, config=DEFAULT_CONFIG, names=DEFAULT_NAMES,
                       custom_patterns=DEFAULT_PATTERNS):
        gfe = GrokFrontend(config=config, custom_patterns_dir=custom_patterns,
                           patterns_names=names)
        return gfe

    def match_any(self, msg_str):
        return self.gfe.match_any(msg_str)
