from datetime import datetime
from flask import jsonify, request, Blueprint

from settings import *
from cores.shodan_explore import ShodanHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")

shodan_app = Blueprint("shodan", __name__)


@shodan_app.route("/explore_host", methods=["POST"])
def get_ip_info():
    """ get specific host information with shodan explore

    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    |  host |  false   |    body     |  str  | the ip address of hosts |
    | history | true   |    body     | 0 / 1 | grab the historical banners for the host, false otherwise |
    | minify | true    |    body     | 0 / 1 | return list of ports and general host information, false otherwise |


    ### request
    ```
    http://127.0.0.1:5000/shodan/explore_host
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```

    ### Output
    * Output_Dir: `output/shodan/`
    * Filename: `host_{$FILE_ID}.json`
    @@@
    """
    the_params = request.json
    shodan_handler = ShodanHandler()
    store_path = "shodan/host_{}.json".format(the_params["host"])
    ip_info = shodan_handler.shodan_host(the_params)
    if type(ip_info) is int:
        response = error_msg(ip_info)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(store_path, ip_info)
    return jsonify(response)


@shodan_app.route("/explore_search", methods=['POST'])
def get_shodan_search():
    """ get specific host information with shodan explore

    @@@
    ### args
    |  args | nullable | request type | type |  remarks |
    |-------|----------|--------------|------|----------|
    | query |  false   |    body     |  str  | Search query |
    | page |  true  | body | int | Page number of the search results |
    | limit | true | body | int | Number of results to return |
    | offset | true | body | int | Search offset to begin getting results from |
    | facets | true | body | int | A list of properties to get summary information on |
    | minify | true | body | int | Whether to minify the banner and only return the important data |


    ### request
    ```
    http://127.0.0.1:5000/shodan/explore_search
    ```

    ### return
    ```json
    {"code": "0", "message": "SUCCESS"}
    ```

    ### Output
    * Output_Dir: `output/shodan/`
    * Filename: `search_{$FILE_ID}.json`
    @@@
    """
    today = datetime.now()
    the_params = request.json
    shodan_handler = ShodanHandler()
    tag_value = the_params["query"].split(" ")[0]
    dt_string = today.strftime("%d_%m_%Y-%H:%M:%S")
    store_path = "shodan/search_{}_{}".format(tag_value, dt_string)
    search_result = shodan_handler.shodan_search(the_params)
    if type(search_result) is int:
        response = error_msg(search_result)
    else:
        response = error_msg(SUCCESS_CODE)
        store_jsonfile(store_path, search_result)
    return jsonify(response)

