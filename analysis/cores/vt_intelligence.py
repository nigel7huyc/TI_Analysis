import vt
import requests

from settings import *
from utils.utils_log import LogFactory
from utils.utils_vt import VTTools
from cores.vt_files import FileHandler

logger = LogFactory.get_log("audit")


class IntelligenceHandler:
    def __init__(self):
        self.url_prefix = "/intelligence"
        self.extra_params = {
            "limit": 40
        }
        self.vt_tools = VTTools()

    def get_ruleset_id(self):
        """
        :return: rules set dictionary, including rules' id and name
        :rtype: dict
        """
        api_flag = 1
        ruleset_id_dict = {}
        params_dict = self.extra_params
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets")
        with vt.Client(api_key, trust_env=True) as client:
            ruleset_json = client.get_json(query_url, params=params_dict)
        if "data" in ruleset_json:
            json_data = ruleset_json["data"]
            if "cursor" in ruleset_json["meta"]:
                cursor_value = ruleset_json["meta"]["cursor"]
                recall_data = self.vt_tools.recall_cursor(cursor_value, query_url, api_flag)
                json_data += recall_data
        else:
            logger.error("[get_ruleset_id] Query Failed, Error Message >> {}".format(ruleset_json))
            return QUERY_FAILED
        for rules_set in json_data:
            id_value = rules_set["id"]
            name_value = rules_set["attributes"]["name"]
            logger.info("[get_ruleset_id] The ID of {} Rules Set is {}".format(name_value, id_value))
            ruleset_id_dict[id_value] = name_value
        return ruleset_id_dict

    @staticmethod
    def remove_duplicate_id(input_data):
        [id_list, output_data] = [[], []]
        for file_element in input_data:
            id_value = file_element["id"]
            if id_value not in id_list:
                id_list.append(id_value)
                output_data.append(file_element)
        return output_data

    def get_notification_files(self, ruleset_id):
        """

        :param ruleset_id: id value of rules
        :type ruleset_id: str
        :return: notifications files information
        :rtype: json list
        """
        api_flag = 1
        params_dict = self.extra_params
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets", ruleset_id, "hunting_notification_files")
        with vt.Client(api_key, trust_env=True) as client:
            notified_files_json = client.get_json(query_url, params=params_dict)
        if "data" in notified_files_json:
            json_data = notified_files_json["data"]
            if "cursor" in notified_files_json["meta"]:
                cursor_value = notified_files_json["meta"]["cursor"]
                recall_data = self.vt_tools.recall_cursor(cursor_value, query_url, api_flag)
                json_data += recall_data
        else:
            logger.error("[get_notification_files] Query Failed, Error Message >> {}".format(notified_files_json))
            return QUERY_FAILED
        distinct_notifications = self.remove_duplicate_id(json_data)
        return distinct_notifications

    def get_pcap_packages(self, id_value, input_name, keyword):
        """

        :param id_value: The value of file's sha256
        :type id_value: str
        :param input_name: the name of sandbox
        :type input_name: str
        :param keyword: the name of family, input with the search API
        :type keyword: str
        :return: None, and store the pcap packages under output/pcap/{$keyword}
        :rtype: NoneType
        """
        api_flag = 1
        the_proxies = {"https": https_proxy}
        file_name = "{}_{}.pcap".format(id_value[:4], input_name.replace(" ", "_"))
        escaped_sandbox = input_name.replace(" ", "%20")
        api_key = self.vt_tools.get_api(api_flag)
        the_header = {"x-apikey": api_key}
        url = 'https://www.virustotal.com/api/v3/file_behaviours/{}_{}/pcap'.format(id_value, escaped_sandbox)
        store_dir = pathlib.Path(os.path.join(output_dir, "pcap", keyword))
        store_dir.parent.mkdir(parents=True, exist_ok=True)
        store_dir.mkdir(parents=True, exist_ok=True)
        destination_path = store_dir.joinpath(file_name).resolve().absolute()
        if destination_path.exists():
            logger.info("[get_pcap_packages] The PCAP Package is Existed")
            return
        try:
            logger.info(
                "[get_pcap_packages] Start to Downloading the PCAP Package from {}".format(url))
            res = requests.get(url, headers=the_header, verify=False, proxies=the_proxies)
            if res.status_code == requests.codes.ok:
                with open(destination_path, 'wb') as f:
                    f.write(res.content)
                logger.info("[get_pcap_packages] Store the PCAP Package >> {}".format(destination_path))
            else:
                logger.error("[get_pcap_packages] Response Code: {}".format(res.status_code))
        except Exception as e:
            logger.error("[get_pcap_packages] Downloading Failed, the Error is {}".format(e))
        return

    def get_search_result(self, input_params):
        """

        :param input_params: the data content of search API
        :type input_params: dict
        :return: distinct search results
        :rtype: json list
        """
        api_flag = 1
        the_params = {}
        file_handler = FileHandler()
        key_word = input_params["key"]
        params_dict = self.extra_params
        params_dict["limit"] = input_params.get("limit", 300)
        params_dict["query"] = input_params.get("query")
        params_dict["order"] = input_params.get("order")
        download_flag = int(input_params.get("download_pcap"))
        for key_value in params_dict.keys():
            if params_dict[key_value] is not None:
                the_params[key_value] = params_dict[key_value]
        logger.info("[get_search_result] The Input Parameters is {}".format(the_params))
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, "search")
        try:
            with vt.Client(api_key, trust_env=True) as client:
                search_results = client.get_json(query_url, params=the_params)
        except Exception as e:
            logger.error("[get_search_result] Query Failed, Error Message >> {}".format(e))
            return QUERY_FAILED
        total_hits = search_results["meta"].get("total_hits")
        logger.info("There are {} Fit Files".format(total_hits))
        json_data = search_results.get("data")
        distinct_search_results = self.remove_duplicate_id(json_data)
        if "have:pcap" in input_params.get("query") and download_flag == 1:
            for element in distinct_search_results:
                file_id = element["id"]
                logger.info("Check the behaviour of {}".format(file_id[:10]))
                behaviours_result = file_handler.file_behaviour(file_id)
                for behaviour_element in behaviours_result["data"]:
                    element_attributes = behaviour_element["attributes"]
                    if "has_pcap" in element_attributes:
                        the_sandbox = element_attributes["sandbox_name"]
                        self.get_pcap_packages(file_id, the_sandbox, key_word)
        return distinct_search_results
