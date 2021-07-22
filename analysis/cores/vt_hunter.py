import os
import vt
import json
import requests
from settings import *
from utils.utils_log import LogFactory

logger = LogFactory.get_log("vt_log")


class LiveHuntHandler:
    def __init__(self):
        self.url_prefix = "/intelligence"
        self.extra_params = {
            "limit": 40
        }

    def get_ruleset_id(self):
        ruleset_id_dict = {}
        api_key = config_module.get_api(1)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets")
        with vt.client(api_key, trust_env=True) as client:
            ruleset_json = client.get_json(query_url, params=self.extra_params)
        if "error" in ruleset_json:
            error_msg = ruleset_json["error"]
            logger.error(error_msg)
            return QUERY_FAILED
        if "next" in ruleset_json["links"]:
            logger.info("[get_ruleset_id] The Next Link is {}".format(ruleset_json["links"]["next"]))
        json_data = ruleset_json["data"]
        for rules_set in json_data:
            id_value = rules_set["id"]
            name_value = rules_set["attributes"]["name"]
            logger.info("The ID of {} Rules Set is {}".format(name_value, id_value))
            ruleset_id_dict[id_value] = name_value
        return ruleset_id_dict

    def get_notification_files(self, ruleset_id):
        api_key = config_module.get_api(1)
        query_url = os.path.join(self.url_prefix, "hunting_rulesets", ruleset_id, "hunting_notification_files")
        with vt.client(api_key, trust_env=True) as client:
            notified_files_json = client.get_json(query_url)
        if "error" in notified_files_json:
            error_msg = notified_files_json["error"]
            logger.error(error_msg)
            return QUERY_FAILED
        if "next" in notified_files_json["links"]:
            logger.info("[get_notification_files] The Next Link for {} Ruleset is {}".format(ruleset_id,
                                                                                             notified_files_json[
                                                                                                 "links"]["next"]))
        json_data = notified_files_json["data"]
        return json_data

    def process_notified_file(self, data_list: list):
        api_key = config_module.get_api(0)
        for data_element in data_list:
            id_value = data_element["id"]
            id_attributes = data_element["attributes"]
