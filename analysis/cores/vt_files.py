import vt
import time
from settings import *
from utils.utils_log import LogFactory
from utils.utils_vt import VTTools

logger = LogFactory.get_log("audit")


class FileHandler:
    def __init__(self):
        self.url_prefix = "/files"
        self.extra_params = {
            "limit": 40
        }
        self.vt_tools = VTTools()

    def file_relationships(self, file_id):
        """

        :param file_id: the value of file's sha256
        :type file_id: str
        :return: the communicate relationship of specific file
        :rtype: json list
        """
        api_flag = 1
        collected_dict = []
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, file_id)
        params_dict = {"relationships": "contacted_ips,contacted_urls,contacted_domains"}
        with vt.Client(api_key, trust_env=True) as client:
            file_json = client.get_json(query_url, params=params_dict)
        if "data" in file_json:
            relationships = file_json["data"]["relationships"]
        else:
            return QUERY_FAILED
        for type_value in relationships:
            the_relationship = relationships[type_value]["data"]
            logger.info(
                "[file_relationships] There are {} element in the relationship of {}".format(len(the_relationship),
                                                                                             type_value))
            if the_relationship:
                relationship_query = os.path.join(query_url, type_value)
                with vt.Client(api_key, trust_env=True) as client:
                    relationships_json = client.get_json(relationship_query, params=self.extra_params)
                    logger.info("[file_relationships] Query the relationship of {}".format(type_value))
                relationships_data = relationships_json["data"]
                if "cursor" in relationships_json["meta"]:
                    cursor_value = relationships_json["meta"]["cursor"]
                    recall_data = self.vt_tools.recall_cursor(cursor_value, relationship_query, api_flag)
                    relationships_data += recall_data
                tmp_dict = {type_value: relationships_data}
                collected_dict.append(tmp_dict)
            else:
                continue
        return collected_dict

    def file_behaviour(self, input_id):
        """

        :param input_id: the value of file's sha256
        :type input_id: str
        :return: the behavior of specified file
        :rtype: json dict
        """
        api_flag = 0
        time.sleep(15)
        params_dict = self.extra_params
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, input_id, "behaviours")
        try:
            with vt.Client(api_key, trust_env=True) as client:
                behaviour_results = client.get_json(query_url, params=params_dict)
                logger.info("[file_behaviour] Get the File Behaviour Results")
        except Exception as e:
            logger.error("[file_behaviour] Query Failed, the Error >> {}".format(e))
            return None
        return behaviour_results
