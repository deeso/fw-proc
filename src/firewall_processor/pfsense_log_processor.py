import os
import toml
import logging
import time
from firewall_processor.client_mongo import FirewallProcMongoClient
from firewall_processor.fluent_client import FluentClient
from firewall_processor.grok_interface import GrokInterface
from multiprocessing import Process, Queue


EM = "[X] Error config does not contain a 'pfsense-log-processor' block."


class PfsenseLogProcessor(object):

    def __init__(self, **kargs):
        self.grok_interface = GrokInterface()
        self.fw_mongoclient_config = kargs.get('mongo-client', {})
        self.fw_mongoclient = None
        if len(self.fw_mongoclient_config) > 0:
            self.fw_mongoclient = \
                FirewallProcMongoClient(**self.fw_mongoclient_config)

        self.postgresclient_config = kargs.get('postgres-client', {})
        self.fw_postgresclient = None
        if len(self.postgresclient_config) > 0:
            self.fw_postgresclient = \
                None

        self.fluentd_config = kargs.get('fluentd-client', {})
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
        self.thread = True
        self.process = False
        self.run_type = kargs.get('run_type', 'thread')
        self.queue = Queue()
        self.sleep_time = kargs.get('sleep_time', 30)

    def submit_results(self, events):
        sr = self.fluentd_client.submit_events(events)
        return sr

    def start(self):
        srp = self.running_processor
        if srp is not None and srp.is_alive():
            return False
        srp = Process(target=self.run, args=(self.queue))
        srp.start()
        return True

    def is_running(self):
        srp = self.running_processor
        if srp is not None and srp.is_alive():
            return True
        return False

    def shutdown(self):
        srp = self.running_processor
        if srp is not None and srp.is_alive():
            self.queue.put('quit')
        time.sleep(self.sleep_time*2)
        if srp.is_alive():
            srp.terminate()
        srp.join()
        return True

    def run(self, queue):
        keep_running = True
        while keep_running:
            try:
                queue.get(timeout=.1)
                break
            except:
                pass

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

    def get_events(self):
        events = []
        if self.fw_mongoclient is not None:
            events = events + self.fw_mongoclient.get_new_events()
        elif self.fw_postgresclient is not None:
            events = events + self.fw_postgresclient.get_new_events()
        return events

    def process_logs(self):
        evts = self.get_events()
        processed_events = self.process_events(self.grok_interface, evts)

        return processed_events

    @classmethod
    def read_parse(cls, filename):
        try:
            os.stat(filename)
        except:
            raise Exception("[X] Error file does not exist")
        toml_data = toml.load(open(filename))
        if 'pfsense-log-processor' not in toml_data:
            raise Exception(EM)
        return cls.parse(toml_data['pfsense-log-processor'])

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
