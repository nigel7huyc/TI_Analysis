import os
import vt
import json
from flask import Flask, jsonfiy, request
from flask_cors import cross_origin

from settings import *
from cores.vt_hunter import LiveHuntHandler

# Initialize APP
app = Flask(__name__)


@app.route('/v0.1/hunting/rules_info', methods=['GET'])
@cross_origin()
def rules_info():
    live_hunter = LiveHuntHandler()
    rules_dict = live_hunter.get_ruleset_id()
    if type(rules_dict) is int:
        response = error_msg(rules_dict)
        response["data"] = {}
    else:
        response = error_msg(SUCCESS_CODE)
        response["data"] = rules_dict
    return jsonfiy(response)

@app.route("/v0.1/hunting/notification_info", methods=["POST"])
@cross_origin()
def notification_info():
    params = request.json
    live_hunter = LiveHuntHandler()
    rule_id_value = params["id"]
    notifications = live_hunter.get_notification_files(rule_id_value)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)


