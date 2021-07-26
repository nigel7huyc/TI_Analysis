import os
import vt
import json
from flask_docs import ApiDoc
from flask_cors import cross_origin
from flask import Flask, jsonify, request

from settings import *
from cores.vt_hunter import LiveHuntHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("hunter")

# Initialize APP
app = Flask(__name__)

ApiDoc(app, title="TI Analysis API Notes", version="1.0.0")


@app.route('/v0.1/hunting/rules_info', methods=['GET'])
@cross_origin()
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


@app.route("/v0.1/hunting/notification_info", methods=["POST"])
@cross_origin()
def notification_info():
    params = request.json
    live_hunter = LiveHuntHandler()
    rule_id_value = params["rules_id"]
    save_path = "hunting_notifications/{}.json".format(rule_id_value)
    logger.info("[notification_info] The Rules ID is {}".format(rule_id_value))
    notifications_data = live_hunter.get_notification_files(rule_id_value)
    if type(notifications_data) is int:
        response = error_msg(notifications_data)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(save_path, notifications_data)
        logger.info("[notification_info] Store Notification Data into {}".format(save_path))
    return jsonify(response)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)


