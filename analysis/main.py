from flask_docs import ApiDoc
from flask import Flask

from utils.utils_log import LogFactory
from apps import bp_files, bp_config, bp_shodan, bp_intelligence

logger = LogFactory.get_log("audit")

# Initialize APP
app = Flask(__name__)

# Api Document needs to be displayed
app.config["API_DOC_MEMBER"] = ["intelligence", "files", "config", "shodan"]

ApiDoc(app, title="TI Analysis API Notes", version="1.0.0")

app.register_blueprint(bp_files, url_prefix="/files")
app.register_blueprint(bp_config, url_prefix="/config")
app.register_blueprint(bp_shodan, url_prefix="/shodan")
app.register_blueprint(bp_intelligence, url_prefix="/intelligence")

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=8000)
