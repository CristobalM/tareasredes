import pickle as pkl
import threading
import os
import time

from dns_parser import DnsParser

CACHE_FILENAME = 'cache_tarea1.pkl'
TIMEOUT_SECONDS = 10

DIRTY_THRESHOLD_NOWAIT = 20


def get_plains_dict_dns(big_dict):
    plains = {}
    for domains, (dns_parser, timestamp) in big_dict.items():
        plains[domains] = (dns_parser.pack(), timestamp)

    return plains


def restore_dns_dict(plain_dict):
    dns_dict = {}
    for domains, (packed_dns, timestamp) in plain_dict.items():
        dns_parsed = DnsParser(packed_dns)
        dns_parsed.process_msg()
        dns_dict[domains] = (dns_parsed, timestamp)
    return dns_dict


class CachePrivate:
    def __init__(self, saved_domains = None):
        self.saved_domains = {} if saved_domains is None else saved_domains
        self._has_init = False
        self._dirty_count = 0
        self._timer = None

    def get_saved_domains(self):
        return self.saved_domains

    def __create_timer(self):
        self.__cancel_timer_if_alive()
        self._timer = threading.Timer(TIMEOUT_SECONDS, self._persist_cache)
        return self._timer

    def __cancel_timer_if_alive(self):
        if self._timer is not None and self._timer.is_alive():
            self._timer.cancel()
            self._timer.join()
            self._timer = None

    def __reset_timer(self):
        self.__cancel_timer_if_alive()
        self.__create_timer().start()

    def init(self):
        self._has_init = True
        self.__reset_timer()

    def set_init(self, boolean):
        self._has_init = boolean

    def save_data(self, domain_name, dns_parser_instance):
        self.saved_domains[domain_name] = (dns_parser_instance, time.time())
        self._dirty_count += 1
        if self._dirty_count < DIRTY_THRESHOLD_NOWAIT:
            self.__reset_timer()
        else:
            self.__cancel_timer_if_alive()
            self._persist_cache()

    def is_saved(self, domain_name):
        exists = domain_name in self.saved_domains
        if not exists:
            return False
        data_retrieved, timestamp = self.saved_domains[domain_name]
        delta_seconds = time.time() - timestamp
        delta_hours = delta_seconds/3600
        if delta_hours > 1:
            del self.saved_domains[domain_name]
            return False

        return True

    def retrieve_data(self, domain_name):
        data_retrieved, _ = self.saved_domains[domain_name]
        return data_retrieved

    def retrieve_data_with_id(self, dns_id, domain_name):
        data = self.retrieve_data(domain_name)
        return data.pack(dns_id)

    def _persist_cache(self):
        CachePrivate.persist_cache(self)
        self._dirty_count = 0


    @staticmethod
    def persist_cache(cache):
        print("Saving cache to disk...")
        cache.set_init(False)
        with open(CACHE_FILENAME, 'wb') as f:
            plain_dict = get_plains_dict_dns(cache.get_saved_domains())
            pkl.dump(plain_dict, f)
        cache.set_init(True)

        print("Done.")


    @staticmethod
    def start_cache():
        if not os.path.isfile(CACHE_FILENAME):
            cache = CachePrivate()
            CachePrivate.persist_cache(cache)
        else:
            with open(CACHE_FILENAME, 'rb') as f:
                plain_dict = pkl.load(f)
                dns_dict = restore_dns_dict(plain_dict)
                cache = CachePrivate(dns_dict)

        cache.init()

        return cache


class Cache:
    instance = None
    @staticmethod
    def get():
        if Cache.instance is None:
            Cache.instance = CachePrivate.start_cache()

        return Cache.instance

