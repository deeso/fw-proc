import json
import socket
from datetime import datetime


class FluentClient(object):

    def __init__(self, host='127.0.0.1', port=42101):
        self.host = host
        self.port = port

    def submit_events(self, events):
        for evt in events:
            if '_id' in evt:
                del evt['_id']
            if 'time' in evt and \
               isinstance(evt['time'], datetime):
                nts = evt['time'].isoformat()
                evt['time'] = nts
            self.send_data(evt)

    def send_data(self, json_data):
        addr = (self.host, self.port)
        data = json.dumps(json_data) + '\n'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, addr)
