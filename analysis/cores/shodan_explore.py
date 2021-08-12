import shodan

from settings import *
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")


class ShodanHandler:
    def __init__(self):
        api_key = shodan_api_key
        self.shodan_api = shodan.Shodan(api_key, proxies=proxies_host)

    def shodan_host(self, host_name: str):
        try:
            host_info = self.shodan_api.host(host_name)
        except Exception as e:
            logger.error("[shodan_host] Shodan Query Host '{}' Information Error, Details: {}".format(host_name, e))
            return QUERY_FAILED
        logger.info("[shodan_host] Queried the Information for the host '{}'".format(host_name))
        return host_info

    def shodan_search(self, query_str):
        try:
            search_results = self.shodan_api.search(query_str)
        except Exception as e:
            logger.error("[shodan_search] Shodan Search with Input Query '{}' Failed, Details: {}".format(query_str, e))
            return QUERY_FAILED
        logger.info("[shodan_search] Searched the Results with the Input Query '{}'".format(query_str))
        return search_results
