import vt
from settings import *
from utils.utils_log import LogFactory
from utils.utils_vt import VTTools

logger = LogFactory.get_log("audit")


class LiveHuntHandler:
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
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets")
        with vt.Client(api_key, trust_env=True) as client:
            ruleset_json = client.get_json(query_url, params=self.extra_params)
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
    def remove_duplicate_files(input_data):
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
        :rtype: list
        """
        api_flag = 1
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets", ruleset_id, "hunting_notification_files")
        with vt.Client(api_key, trust_env=True) as client:
            notified_files_json = client.get_json(query_url, params=self.extra_params)
        if "data" in notified_files_json:
            json_data = notified_files_json["data"]
            if "cursor" in notified_files_json["meta"]:
                cursor_value = notified_files_json["meta"]["cursor"]
                recall_data = self.vt_tools.recall_cursor(cursor_value, query_url, api_flag)
                json_data += recall_data
        else:
            logger.error("[get_notification_files] Query Failed, Error Message >> {}".format(notified_files_json))
            return QUERY_FAILED
        distinct_notifications = self.remove_duplicate_files(json_data)
        return distinct_notifications
