import os
import vt
import json
import pathlib

from settings import *
from cores.vt_hunter import LiveHuntHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("vt_log")

def get_live_hunt_results():
    live_hunter = LiveHuntHandler()
    ruleset_id_dict = live_hunter.get_ruleset_id()
    json_dir = root_path.joinpath("output/ruleset_notifications").absolute().resolve()
    if not os.path.exists(json_dir):
        os.mkdir(json_dir)
        logger.info("[give_live_hunt_results] Create the Directory, Named {}".format(json_dir))
    for ruleset_id in ruleset_id_dict:
        ruleset_name = ruleset_id_dict[ruleset_id]
        res_data = live_hunter.get_notification_files(ruleset_id)
        if type(res_data) is int:
            logger.error("[give_live_hunt_results] Get Notification Files Failed, Error Code {}".format(res_data))
            continue
        else:
            json_data = json.dumps(res_data, indent=4)
            json_path = json_dir.joinpath("{}.json".format(ruleset_name)).absolute().resolve()
            json_path.write_text(json_data)
            logger.info("[give_live_hunt_results] Write Data into {} File".format(json_path))
    return SUCCESS


if __name__ == '__main__':
    get_live_hunt_results()


