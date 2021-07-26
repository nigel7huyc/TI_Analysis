import os
import pathlib

# State Root Path
file_path = pathlib.Path(__file__).absolute().resolve()
root_path = file_path.joinpath("../../").absolute().resolve()

# State API Variables
enterprise_api_key = os.getenv("ENTERPRISE_TOKEN")
private_api_key = os.getenv("PRIVATE_TOKEN")
log_dir = os.getenv("LOG_DIR", os.path.join(root_path, "log/analysis"))
conf_dir = os.getenv("CONF_DIR", os.path.join(root_path, "conf"))
analysis_dir = os.getenv("ANALYSIS_DIR", os.path.join(root_path, "analysis"))

# State Result Code
SUCCESS_CODE = 0
QUERY_FAILED = -1

# Define Error Message Function
def error_msg(error_code):
    error_dict = {
        0: "Operation Success",
        -1: "Query Failed"
    }
    res = {"code": error_code, "message": error_dict[error_code]}
    return res