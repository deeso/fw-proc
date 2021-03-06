from pymongo import MongoClient
from datetime import datetime
from datetime import timedelta

TS_FMT = '%Y-%m-%dT%H:%M:%S'
TS_FMT_D = '%Y-%m-%dT%H:%M:%S.%f'
ID = '_id'


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

    def upsert(self, id_key, id_key_val, json_data):
        c = self.new_client()
        col = c[self.database][self.collection]
        d = col.find_one({id_key: id_key_val})
        r = None
        # print (d)
        if d is not None:
            d.update(json_data)
            r = col.update({id_key: id_key_val}, {'$set': d})
            # print (r)
        else:
            _jd = json_data.copy()
            _jd[id_key] = id_key_val
            r = col.insert(_jd)
            # print (r)
        c.close()
        return r

    def find_in_time_range(self, id_key, start, end):
        query = {id_key: {'$gte': start, '$lt': end}}
        c = self.new_client()
        col = c[self.database][self.collection]
        evts = [i for i in col.find(query)]
        c.close()
        return evts

    def find_min(self, id_key):
        query = {id_key: {"$exists": True}}
        c = self.new_client()
        col = c[self.database][self.collection]
        evt = col.find_one(query, sort=[(id_key, 1)])
        return evt[id_key]

    def find_one(self, query):
        c = self.new_client()
        col = c[self.database][self.collection]
        return col.find_one(query)


class FirewallProcMongoClient(Client):

    def __init__(self, host='127.0.0.1', port=27017,
                 dest_database='firewall-processor',
                 dest_collection='state', start_time=None,
                 lock_key='lock',
                 window_secs=60, source_db='fluent',
                 source_collection='firewall-raw', source_key='time',
                 source_host=None, source_port=None):
        Client.__init__(self, host, port, dest_database, dest_collection)
        source_host = host if source_host is None else source_host
        source_port = port if source_port is None else source_port

        self.source = Client(source_host, source_port,
                             source_db, source_collection)

        if start_time is None:
            start_time = datetime.utcnow()
        elif start_time.find('.') > 0:
            start_time = datetime.strptime(start_time, TS_FMT_D)
        else:
            start_time = datetime.strptime(start_time, TS_FMT)

        mt = self.source.find_min(source_key)
        if start_time < mt:
            start_time = mt

        self.source_key = source_key
        self.init_state(start_time)
        self.window_secs = window_secs

    def init_state(self, start_time):
        r = {'lock': False,
             'start_time': start_time,
             'last_look': datetime.utcnow(),
             }
        v = self.find_one({})
        if v is None:
            self.insert(r)
            return True
        return False

    # terrible synchronization pattern
    def set_lock(self):
        v = self.find_one({})
        if not v['lock']:
            v['lock'] = True
            k = v[ID]
            del v[ID]
            # print (v)
            if not self.find_one({})['lock']:
                self.upsert(ID, k, v)
                return True
        return False

    def release_lock(self, last_look=None, new_start_time=None):
        v = self.find_one({})
        # print (last_look, new_start_time)
        # print (v)
        v['last_look'] = last_look if last_look is not None \
            else v['last_look']
        v['start_time'] = new_start_time if new_start_time is not None \
            else v['start_time']
        if v['lock']:
            v['lock'] = False
            k = v[ID]
            del v[ID]
            # print(v)
            self.upsert(ID, k, v)
            return True
        return False

    def get_new_events(self):
        got_lock = self.set_lock()
        if not got_lock:
            return []
        v = self.find_one({})
        start = v['start_time']
        end = start + timedelta(seconds=self.window_secs)
        events = self.source.find_in_time_range(self.source_key, start, end)
        self.release_lock(last_look=datetime.utcnow(), new_start_time=end)
        return events
