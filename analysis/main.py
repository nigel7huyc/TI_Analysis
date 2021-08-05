import os
import vt
import json
from flask_docs import ApiDoc
from flask_cors import cross_origin
from flask import Flask, jsonify, request, Blueprint

from settings import *
from cores.vt_intelligence import IntelligenceHandler
from cores.vt_files import FileHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")

# Initialize APP
app = Flask(__name__)

# Api Document needs to be displayed
app.config["API_DOC_MEMBER"] = ["intelligence", "files", "config"]

ApiDoc(app, title="TI Analysis API Notes", version="1.0.0")

files = Blueprint("files", __name__)
config = Blueprint("config", __name__)
intelligence = Blueprint("intelligence", __name__)


@config.route('/health', methods=['GET'])
def get_health_status():
    """ check the health of api

    @@@
    ### args
    None

    ### request
    ```
    http://127.0.0.1:5000/config/health
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```
    @@@
    """
    response = error_msg(HEALTH_OK)
    return jsonify(response)


@intelligence.route('/v3/rules_info', methods=['GET'])
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


@intelligence.route("/v3/notification_info", methods=["POST"])
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
    save_path = "hunting_notifications/{}_notifications.json".format(rule_id_value[:10])
    logger.info("[notification_info] The Rules ID is {}".format(rule_id_value))
    notifications_data = intelligence_handler.get_notification_files(rule_id_value)
    if type(notifications_data) is int:
        response = error_msg(notifications_data)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, notifications_data)
        logger.info("[notification_info] Store Notification Data into {}".format(save_path))
    return jsonify(response)


@intelligence.route("/v3/search", methods=["POST"])
def intelligence_search():
    """ search with specific query conditions
    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    |  key  |  false   |     body     | str  |  The keyword of this search    |
    | limit |   True   |     body     | str  |  The number of element in this search, less than 300     |
    | query |  false   |     body     | str  |  The condition of this search        |
    | order |   True   |     body     | str  |  The order of this search result        |


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
    * pcap packages (if `have:pcap` in query)
        * Output_Dir: `output/pcap/`
        * Filename: `{$KEY}/{$FILE_ID[:4]}_{$SANDBOX_NAME}.pcap`
    @@@
    """
    params = request.json
    query_info = params.get("query")
    intelligence_handler = IntelligenceHandler()
    save_path = "search_results/{}_search.json".format("_".join(query_info.split(" ")))
    search_results = intelligence_handler.get_search_result(params)
    if type(search_results) is int:
        response = error_msg(search_results)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, search_results)
        logger.info("[intelligence_search] Store Notification Data into {}".format(save_path))
    return jsonify(response)


@files.route("/v3/relationships", methods=["POST"])
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
    save_path = "files/{}_relationships.json".format(file_id_value[:10])
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


app.register_blueprint(files, url_prefix="/files")
app.register_blueprint(config, url_prefix="/config")
app.register_blueprint(intelligence, url_prefix="/intelligence")

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)
