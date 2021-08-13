from flask_docs import ApiDoc
from flask import Flask

from utils.utils_log import LogFactory
from apps import bp_vt, bp_config, bp_shodan

logger = LogFactory.get_log("audit")

# Initialize APP
app = Flask(__name__)

# Api Document needs to be displayed
app.config["API_DOC_MEMBER"] = ["vt", "config", "shodan"]

ApiDoc(app, title="TI Analysis API Notes", version="1.0.0")

app.register_blueprint(bp_vt, url_prefix="/vt")
app.register_blueprint(bp_config, url_prefix="/config")
app.register_blueprint(bp_shodan, url_prefix="/shodan")

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)
