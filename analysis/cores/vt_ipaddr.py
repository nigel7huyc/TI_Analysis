import vt

from settings import *
from utils.utils_log import LogFactory
from utils.utils_vt import VTTools

logger = LogFactory.get_log("audit")


class IPHandler:
    def __init__(self):
        self.url_prefix = "/ip_addresses"
        self.extra_params = {
            "limit": 40
        }
        self.vt_tools = VTTools()

    def query_ip(self, input_ip):
        """
        
        :param input_ip: the specific host ip address
        :type input_ip: str 
        :return: the ip information
        :rtype: json dict
        """
        api_flag = 0
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, input_ip)
        with vt.Client(api_key, trust_env=True) as client:
            file_json = client.get_json(query_url)
        ip_info = file_json.get("data")
        if ip_info is None:
            return QUERY_FAILED
        else:
            return ip_info

    def get_communicate_files(self, input_ip):
        """

        :param input_ip: the specific host ip address
        :type input_ip: str
        :return: files which communicate to the specific ip address
        :rtype: json list
        """
        api_flag = 0
        params_dict = self.extra_params
        api_key = self.vt_tools.get_api(api_flag)
        query_url = os.path.join(self.url_prefix, input_ip, "communicating_files")
        with vt.Client(api_key, trust_env=True) as client:
            file_json = client.get_json(query_url, params=params_dict)
        files_data = file_json.get("data")
        if files_data is None:
            return QUERY_FAILED
        meta_data = file_json.get("meta")
        if "cursor" in meta_data:
            cursor_value = meta_data["cursor"]
            recall_data = self.vt_tools.recall_cursor(cursor_value, query_url, api_flag)
            files_data += recall_data
        return files_data


