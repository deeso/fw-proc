from pymongo import MongoClient
from datetime import datetime
from datetime import timedelta

class Client(object):
    def __init__(self, host, port, database, collection):
        self.host = host
        self.port = port
        self.database = database
        self.collection = collection

    def new_client(self):
        return MongoClient(self.host, self.port)

    def insert(self, json_data):
        c = self.new_client()
        col = c[self.database][self.collection]
        r = col.insert(json_data)
        c.close()
        return r

    def upsert(self, id_key, json_data):
        v = json_data[id_key]
        c = self.new_client()
        col = c[self.database][self.collection]
        r = col.update({id_key: v}, json_data)
        c.close()
        return r

    def find_in_time_range(self, id_key, start, end):
        query = {id_key: {'$gte': start, '$lt': end}}
        c = self.new_client()
        col = c[self.database][self.collection]
        evts = [i for i in col.find(query)]
        c.close()
        return evts

class StateConnection(Client):

    def __init__(self, host, port, database='firewall-processor',
                 collection='state', start_time=None, lock_key='lock',
                 window_secs=60, target_db='fluent',
                 target_collection='firewall-raw', target_key='time'):
        Client.__init__(self, host, port, database, collection)
        start_time = datetime.utcnow() if start_time is None\
            else start_time
        self.init_state()

    def init_state(self, start_time):
        r = {'lock': False,
             'start_time': start_time,
             'last_look': datetime.utcnow(),
             }
        v = self.new_client().find_one({})
        if v is None:
            self.new_client().insert(r)
            return True
        return False

    # terrible synchronization pattern
    def set_lock(self):
        v = self.new_client().find_one({})
        if not v['lock']:
            v['lock'] = True
            k = v['_id']
            del v['_id']
            if not self.new_client().find_one({})['lock']:
                self.new_client().upsert(k, v)
                return True
        return False

    def release_lock(self, last_look=None, start_time=None):
        v = self.new_client().find_one({})
        if v['lock']:
            v['lock'] = False
            k = v['_id']
            del v['_id']
            self.new_client().upsert(k, v)
            return True
        return False

    def get_new_events(self):
        got_lock = self.set_lock()
        if not got_lock:
            return []
        v = self.new_client().find_one({})
        start = v['start_time']
        end = start + timedelta(seconds=self.window_secs)


        self.release_lock()


