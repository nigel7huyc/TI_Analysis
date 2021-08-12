from datetime import datetime
from flask import jsonify, request, Blueprint

from settings import *
from cores.vt_intelligence import IntelligenceHandler
from cores.vt_files import FileHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")

files_app = Blueprint("files", __name__)
intelligence_app = Blueprint("intelligence", __name__)


@intelligence_app.route('/v3/rules_info', methods=['GET'])
def rules_info():
    """ get enabled ruleset information

    @@@
    ### args
    None

    ### request
    ```
    http://127.0.0.1:5000/intelligence/v3/rules_info
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS", "data": {ruleset_id_X: ruleset_name_X, ...}}
    ```
    @@@
    """
    intelligence_handler = IntelligenceHandler()
    rules_dict = intelligence_handler.get_ruleset_id()
    if type(rules_dict) is int or rules_dict is None:
        response = error_msg(rules_dict)
        response["data"] = {}
    else:
        response = error_msg(SUCCESS_CODE)
        response["data"] = rules_dict
    return jsonify(response)


@intelligence_app.route("/v3/notification_info", methods=["POST"])
def notification_info():
    """ get the notifications of specific rules set id

    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    |  rules_id |  false   |    body     | str  | The id of specific rules set |


    ### request
    ```
    http://127.0.0.1:5000/intelligence/v3/notification_info
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```

    ### Output
    * Output_Dir: `output/hunting_notifications/`
    * Filename: `{$RULESET_ID}_notifications.json`
    @@@
    """
    params = request.json
    intelligence_handler = IntelligenceHandler()
    rule_id_value = params["rules_id"]
    save_path = "hunting_notifications/{}_notifications.json".format(rule_id_value[:8])
    logger.info("[notification_info] The Rules ID is {}".format(rule_id_value))
    notifications_data = intelligence_handler.get_notification_files(rule_id_value)
    if type(notifications_data) is int:
        response = error_msg(notifications_data)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, notifications_data)
        logger.info("[notification_info] Store Notification Data into {}".format(save_path))
    return jsonify(response)


@intelligence_app.route("/v3/search", methods=["POST"])
def intelligence_search():
    """ search with specific query conditions
    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    |  tag  |  false   |     body     | str  |  The directory keyword of store pcap packages in the search   |
    | limit |   True   |     body     | int  |  The number of element in this search, less than 300, default 40     |
    | query |  false   |     body     | str  |  The condition of this search        |
    | order |   True   |     body     | str  |  The order of this search result        |
    | download_pcap  |   True  |     body     |  0 / 1 | Download or not the pcap packages |


    ### request
    ```
    http://127.0.0.1:5000/intelligence/v3/search
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```

    ### Output
    * search result record
        * Output_Dir: `output/search_results/`
        * Filename: `{$INPUT_QUERY_CONDITIONS}_search.json`
    * pcap packages (if `have:pcap` in query AND `download_pcap==1`)
        * Output_Dir: `output/pcap/`
        * Filename: `{$KEY}/{$FILE_ID[:8]}_{$SANDBOX_NAME}.pcap`
    @@@
    """
    params = request.json
    today = datetime.now()
    file_handler = FileHandler()
    tag_value = params.get("tag", "files")
    query_info = params.get("query")
    dt_string = today.strftime("%d_%m_%Y-%H:%M:%S")
    download_flag = int(params.get("download_pcap"))
    intelligence_handler = IntelligenceHandler()
    save_path = "search_results/{}-{}_search.json".format(dt_string, "_".join(query_info.split(" ")))
    search_results = intelligence_handler.get_search_result(params)
    if type(search_results) is int:
        response = error_msg(search_results)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, search_results)
        logger.info("[intelligence_search] Store Notification Data into {}".format(save_path))
    if "have:pcap" in query_info and download_flag == 1:
        for element in search_results:
            file_id = element["id"]
            logger.info("Check the behaviour of {}".format(file_id[:8]))
            behaviours_result = file_handler.file_behaviour(file_id)
            for behaviour_element in behaviours_result["data"]:
                element_attributes = behaviour_element["attributes"]
                if "has_pcap" in element_attributes:
                    the_sandbox = element_attributes["sandbox_name"]
                    intelligence_handler.get_pcap_packages(file_id, the_sandbox, tag_value)
    return jsonify(response)


@files_app.route("/v3/behaviours", methods=["POST"])
def get_file_behaviours():
    """ Query the behaviours with specific file
        @@@
        ### args
        |  args | nullable | request type | type |  remarks |
        |-------|----------|--------------|------|----------|
        |  tag  |  false   |     body     | str  |  The directory keyword of store pcap packages in the search   |
        | file_id |  false   |     body     | str  |  The file is specified to search its behavior |
        | download_pcap  |   True  |     body     |  0 / 1 | Download or not the pcap packages |


        ### request
        ```
        http://127.0.0.1:5000/intelligence/v3/behaviours
        ```

        ### return
        ```json
        {"code": "0", "message": "SUCCESS"}
        ```

        ### Output
        * search result record
            * Output_Dir: `output/behaviours/`
            * Filename: `{$FILE_ID[:8]}_behaviours.json`
        * pcap packages (if `download_pcap==1`)
            * Output_Dir: `output/pcap/`
            * Filename: `{$KEY}/{$FILE_ID[:8]}_{$SANDBOX_NAME}.pcap`
        @@@
        """
    params = request.json
    file_handler = FileHandler()
    tag_value = params.get("tag", "files")
    file_id = params.get("file_id")
    intelligence_handler = IntelligenceHandler()
    download_flag = int(params.get("download_pcap", 0))
    save_path = "behaviours/{}_behaviours.json".format(file_id[:8])
    logger.info("[get_file_behaviours] Start to Grab the file's behaviour for {}".format(file_id))
    results = file_handler.file_behaviour(file_id)
    if results is None:
        response = error_msg(QUERY_FAILED)
    else:
        response = error_msg(SUCCESS_CODE)
        the_file_behaviours = results["data"]
        store_jsonfile(save_path, the_file_behaviours)
        if download_flag:
            logger.info("[get_file_behaviours] Start to Download the PCAP Packages")
            for element in the_file_behaviours:
                attributes_content = element["attributes"]
                the_sandbox = attributes_content.get("sandbox_name")
                if the_sandbox is not None:
                    intelligence_handler.get_pcap_packages(file_id, the_sandbox, tag_value)
    return jsonify(response)


@files_app.route("/v3/relationships", methods=["POST"])
def relationship_contents():
    """ get the communicate relationships of the specific file

    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    |  file_id |  false   |    body     | str  | The id of specific file |


    ### request
    ```
    http://127.0.0.1:5000/files/v3/relationships
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```

    ### Output
    * Output_Dir: `output/files/`
    * Filename: `{$FILE_ID}_relationships.json`
    @@@
    """
    params = request.json
    file_handler = FileHandler()
    file_id_value = params["file_id"]
    save_path = "files/{}_relationships.json".format(file_id_value[:8])
    logger.info("[relationship_contents] The File ID is {}".format(file_id_value))
    relationship_data = file_handler.file_relationships(file_id_value)
    if type(relationship_data) is int:
        response = error_msg(relationship_data)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, relationship_data)
        logger.info(
            "[relationship_contents] Store Relationships Data into {}, There are {} Objects in JSON Files".format(
                save_path, len(relationship_data)))
    return jsonify(response)