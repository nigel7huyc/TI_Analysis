from flask import jsonify, Blueprint

from settings import *
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")


config_app = Blueprint("config", __name__)


@config_app.route('/health', methods=['GET'])
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