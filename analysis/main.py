import os
import vt
import json
from flask_docs import ApiDoc
from flask_cors import cross_origin
from flask import Flask, jsonify, request

from settings import *
from cores.vt_hunter import LiveHuntHandler
from cores.vt_files import FileHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("hunter")

# Initialize APP
app = Flask(__name__)

ApiDoc(app, title="TI Analysis API Notes", version="1.0.0")


@app.route('/health', methods=['GET'])
def get_health_status():
    response = error_msg(HEALTH_OK)
    return jsonify(response)


@app.route('/v3/hunting/rules_info', methods=['GET'])
def rules_info():
    live_hunter = LiveHuntHandler()
    rules_dict = live_hunter.get_ruleset_id()
    if type(rules_dict) is int or rules_dict is None:
        response = error_msg(rules_dict)
        response["data"] = {}
    else:
        response = error_msg(SUCCESS_CODE)
        response["data"] = rules_dict
    return jsonify(response)


@app.route("/v3/hunting/notification_info", methods=["POST"])
def notification_info():
    params = request.json
    live_hunter = LiveHuntHandler()
    rule_id_value = params["rules_id"]
    save_path = "hunting_notifications/{}_notifications.json".format(rule_id_value[:10])
    logger.info("[notification_info] The Rules ID is {}".format(rule_id_value))
    notifications_data = live_hunter.get_notification_files(rule_id_value)
    if type(notifications_data) is int:
        response = error_msg(notifications_data)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, notifications_data)
        logger.info("[notification_info] Store Notification Data into {}".format(save_path))
    return jsonify(response)

@app.route("/v3/Files/relationships", methods=["POST"])
def relationship_contents():
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
        logger.info("[relationship_contents] Store Relationships Data into {}".format(save_path))
    return jsonify(response)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)


