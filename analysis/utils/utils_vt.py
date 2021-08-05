import vt
from settings import *
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")


class VTTools:
    def __init__(self):
        self.extra_params = {
            "limit": 40
        }

    @staticmethod
    def get_api(is_enterprise):
        if is_enterprise:
            api_key = enterprise_api_key
            logger.info("[get_api] Enterprise API Key")
        else:
            api_key = private_api_key
            logger.info("[get_api] Private API Key")
        return api_key

    def recall_cursor(self, input_cursor, input_url, flag):
        final_data = []
        params_dict = self.extra_params
        cursor_value = input_cursor
        api_key = self.get_api(flag)
        with vt.Client(api_key, trust_env=True) as client:
            while True:
                params_dict["cursor"] = cursor_value
                logger.info("[recall_cursor] The Header of Cursor {}".format(params_dict["cursor"][:10]))
                logger.info("[recall_cursor] Query URL is {}".format(input_url))
                json_data = client.get_json(input_url, params=params_dict)
                if "data" in json_data:
                    final_data += json_data["data"]
                    logger.info("[recall_cursor] There are {} element in {}".format(len(final_data), params_dict["cursor"][:10]))
                    if "cursor" in json_data["meta"]:
                        cursor_value = json_data["meta"]["cursor"]
                    else:
                        logger.info("[recall_cursor] There is not Cursor in Response, Break Loop")
                        break
                else:
                    logger.error("[recall_cursor] Query Failed, Break Loop")
                    break
        return final_data
