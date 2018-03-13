from firewall_processor.pfsense_log_processor import PfsenseLogProcessor
import sys
import time
import argparse
import logging

logging.getLogger().setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s - %(name)s] %(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)


CMD_DESC = 'pfsense firewall log message processing.'
parser = argparse.ArgumentParser(description=CMD_DESC)
parser.add_argument('-config', type=str, default=None,
                    help='config file containing a decription of io and flows')

if __name__ == "__main__":
    args = parser.parse_args()
    if args.config is None:
        parser.print_help()
        sys.exit(1)

    fw_proc = PfsenseLogProcessor.read_parse(args.config)

    fw_proc.start()

    while fw_proc.is_running():
        try:
            time.sleep(fw_proc.sleep_window)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt detected shutting down")
            fw_proc.shutdown()
        except:
            logging.info("Exception detected")
            fw_proc.shutdown()
