import logging
from firewall_processor.base_log_processor import BaseLogProcessor
from firewall_processor.grok_interface import GrokInterface
GROK_INTEFACE = GrokInterface()


class PfsenseLogProcessor(BaseLogProcessor):

    def __init__(self, **kargs):
        BaseLogProcessor.__init__(self, **kargs)

    @classmethod
    def extract_event_data(self, message, **kargs):
        parsed_results = None
        if message is None:
            return parsed_results
        results = GROK_INTEFACE.match_any(message)
        outcome = results.get('outcome', False)
        rtype = results.get('type', '')
        if outcome and rtype == 'pattern':
            parsed_results = results.get('rule_results', {})
        elif outcome and rtype == 'chains':
            rule_results = results.get('rule_results', None)
            parsed_results = rule_results.get('rule_results', None)
        return parsed_results

    @classmethod
    def process_events(cls, events, **kargs):
        processed_events = []
        updated_events = 0
        logging.debug("Processing %d events" % len(events))
        for evt in events:
            if '_id' in evt:
                del evt['_id']
            if 'time' in evt:
                cls.convert_time(evt)
            parsed_results = None
            message = evt.get('message', None)
            parsed_results = cls.extract_event_data(message)
            if parsed_results is not None:
                updated_events += 1
                evt.update(parsed_results)
            processed_events.append(evt)
        logging.info("Processed %d events and updated %d")
        return processed_events

    @classmethod
    def parse(cls, config_dict):
        new_config = {}

        new_config['sleep_time'] = config_dict.get('sleep_time', 30)
        new_config['mongo-client'] = config_dict.get('mongo-client', {})
        new_config['postgres-client'] = config_dict.get('postgres-client', {})
        new_config['fluentd-client'] = config_dict.get('fluentd-client', {})

        if 'host' not in new_config['fluentd-client']:
            raise Exception("Missing 'host' for fluentd configuration")
        elif 'port' not in new_config['fluentd-client']:
            raise Exception("Missing 'port' for fluentd configuration")

        return PfsenseLogProcessor(**new_config)
