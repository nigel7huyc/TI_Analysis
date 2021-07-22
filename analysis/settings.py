import os
import pathlib

# State Root Path
file_path = pathlib.Path(__file__).absolute().resolve()
root_path = file_path.joinpath("../../").absolute().resolve()

# State API Variables
enterprise_api_key = os.getenv("ENTERPRISE_TOKEN")
private_api_key = os.getenv("PRIVATE_TOKEN")
log_dir = os.getenv("LOG_DIR", os.path.join(root_path, "log"))
conf_dir = os.getenv("CONF_DIR", os.path.join(root_path, "conf"))
analysis_dir = os.getenv("ANALYSIS_DIR", os.path.join(root_path, "analysis"))

# State Result Code
SUCCESS = 0
QUERY_FAILED = -1

# Define Store Function
def store_response(output_value, output_file:str):
    dir_object = pathlib.Path(output_file)
    dir_object.write_text(output_value)

# Define VT Configuration
class ConfigClient:
    def __init__(self):
        self.api = None
        self.url_prefix = "https://www.virustotal.com/api/v3"

    def get_api(self, is_enterprise):
        if is_enterprise:
            self.api = enterprise_api_key
        else:
            self.api = private_api_key
        return self.api

    def get_url(self, collection_name):
        if collection_name is None:
            url = self.url_prefix
        else:
            url = os.path.join(self.url_prefix, collection_name)
        return url

# State VT Variable

config_module = ConfigClient()
