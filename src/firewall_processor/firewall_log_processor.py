import logging
import time
from client_mongo import FirewallProcMongoClient
from fluent_client import FluentClient
from grok_interface import GrokInterface


class FirewallLogProcessor(object):

    def __init__(self, **kargs):
        self.grok_interface = GrokInterface()
        self.fw_mongoclient_config = kargs.get('mongoclient', {})
        self.fw_mongoclient = None
        if len(self.mongoclient_config) > 0:
            self.fw_mongoclient = \
                FirewallProcMongoClient(**self.fw_mongoclient_config)

        self.postgresclient_config = kargs.get('postgresclient', {})
        self.fw_postgresclient = None
        if len(self.mongoclient_config) > 0:
            self.fw_postgresclient = \
                None

        self.fluentd_config = kargs.get('fluentdcontent', {})
        self.fluentd_client = None
        if len(self.fluentd_config) > 0:
            self.fluentd_client = FluentClient(**self.fluentd_config)

        if self.fw_mongoclient is None and \
           self.fw_postgresclient is None:
            raise Exception("No source for logs specified")

        if self.fluentd_client is None:
            raise Exception("No destination for processed logs specified")

        self.running_processor = None
        self.keep_running = False
        self.sleep_time = kargs.get('sleep_time', 30)

    def submit_results(self, events):
        self.fluentd_client.submit_events(events)

    def run(self):
        self.keep_running = True
        while self.keep_running:
            results = self.process_logs()
            self.submit_results(results)
            if self.sleep_time > 0.0:
                time.sleep(self.sleep_time)

    @classmethod
    def extract_event_data(self, grok_interface, message):
        parsed_results = None
        if message is None:
            return parsed_results
        results = grok_interface.match_any(message)
        outcome = results.get('outcome', False)
        rtype = results.get('type', '')
        if outcome and rtype == 'pattern':
            parsed_results = results.get('rule_results', {})
        elif outcome and rtype == 'chains':
            rule_results = results.get('rule_results', None)
            parsed_results = rule_results.get('rule_results', None)
        return parsed_results

    @classmethod
    def convert_time(cls, evt):
        dt = evt['time'] if 'time' in evt else None
        if dt is not None:
            nts = dt.isoformat()
            evt['time'] = nts

    @classmethod
    def process_events(cls, grok_interface, events):
        processed_events = []
        updated_events = 0
        logging.debug("Processing %d events" % len(events))
        for evt in events:
            if '_id' in evt:
                del evt['_id']
            if 'time' in evt:
                cls.convert_time(evt)
            parsed_results = None
            if 'ident' in evt and evt['ident'] == 'filterlog':
                # use rule-chains to extract the message
                message = evt.get('message', None)
                parsed_results = cls.extract_event_data(grok_interface,
                                                        message)
                if parsed_results is not None:
                    updated_events += 1
                    evt.update(parsed_results)
            processed_events.append(evt)
        logging.info("Processed %d events and updated %d")
        return processed_events

    def process_logs(self):
        events = []
        if self.fw_mongoclient is not None:
            events = events + self.fw_mongoclient.get_new_events()
        elif self.fw_postgresclient is not None:
            events = events + self.fw_postgresclient.get_new_events()

        processed_events = self.process_events(self.grok_interface,
                                               events)
        return processed_events

    @classmethod
    def parse(cls, config_dict):
        new_config = {}

        new_config['sleep_time'] = config_dict.get('sleep_time', 30)
        new_config['mongoclient'] = config_dict.get('mongoclient', {})
        new_config['postgresclient'] = config_dict.get('postgresclient', {})
        new_config['fluentd'] = config_dict.get('fluentd', {})

        if 'host' not in new_config['fluentd']:
            raise Exception("Missing 'host' for fluentd configuration")
        elif 'port' not in new_config['fluentd']:
            raise Exception("Missing 'port' for fluentd configuration")

        return FirewallLogProcessor(**new_config)
