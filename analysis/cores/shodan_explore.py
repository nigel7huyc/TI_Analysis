import shodan

from settings import *
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")


class ShodanHandler:
    def __init__(self):
        api_key = shodan_api_key
        self.shodan_api = shodan.Shodan(api_key, proxies=proxies_host)

    def shodan_host(self, input_params: dict):
        host_name = input_params.get("host")
        history_value = input_params.get("history", 0)
        minify_value = input_params.get("minify", 0)
        try:
            host_info = self.shodan_api.host(host_name, history_value, minify_value)
        except Exception as e:
            logger.error("[shodan_host] Shodan Query Host '{}' Information Error, Details: {}".format(host_name, e))
            return QUERY_FAILED
        logger.info("[shodan_host] Queried the Information for the host '{}'".format(host_name))
        return host_info

    def shodan_search(self, input_params: dict):
        query_value = input_params.get("query")
        page_value = input_params.get("page", 1)
        limit_value = input_params.get("limit")
        offset_value = input_params.get("offset")
        facets_value = input_params.get("facets")
        minify_value = input_params.get("minify")
        try:
            search_results = self.shodan_api.search(query_value, page_value, limit_value, offset_value, facets_value,
                                                    minify_value)
        except Exception as e:
            logger.error(
                "[shodan_search] Shodan Search with Input Query '{}' Failed, Details: {}".format(query_value, e))
            return QUERY_FAILED
        logger.info("[shodan_search] Searched the Results with the Input Query '{}'".format(query_value))
        return search_results
