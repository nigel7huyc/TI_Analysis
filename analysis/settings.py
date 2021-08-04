import os
import json
import pathlib

# State Root Path
file_path = pathlib.Path(__file__).absolute().resolve()
root_path = file_path.joinpath("../../").absolute().resolve()

# State API Variables
enterprise_api_key = os.getenv("ENTERPRISE_TOKEN")
private_api_key = os.getenv("PRIVATE_TOKEN")
conf_dir = os.getenv("CONF_DIR", os.path.join(root_path, "conf"))
output_dir = os.getenv("OUTPUT_DIR", os.path.join(root_path, "output"))
log_dir = os.getenv("LOG_DIR", os.path.join(root_path, "log/analysis"))
analysis_dir = os.getenv("ANALYSIS_DIR", os.path.join(root_path, "analysis"))

# State Result Code
HEALTH_OK = 0
SUCCESS_CODE = 0
QUERY_FAILED = -1


# Define Store Directory
def store_jsonfile(input_path, input_data):
    json_path = pathlib.Path(output_dir).joinpath(input_path).absolute().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(input_data, indent=4, sort_keys=True))


# Define Error Message Function
def error_msg(error_code):
    error_dict = {
        0: "Operation Success",
        -1: "Query Failed"
    }
    res = {"code": error_code, "message": error_dict[error_code]}
    return res