from settings import *


class LogConfigReader:
    def __init__(self):
        self.conf_dir = conf_dir
        self.log_dir = log_dir

    def get_log_conf(self):
        log_conf_path = pathlib.Path(self.conf_dir).joinpath("log_config.json").resolve().absolute()
        log_format_data = json.loads(log_conf_path.read_text())
        return log_format_data

    def get_log_path(self, input_name):
        log_data = self.get_log_conf()
        log_path_info = log_data["log_name"][input_name]
        log_path = os.path.join(self.log_dir, log_path_info)
        return log_path

    def get_log_format(self):
        log_data = self.get_log_conf()
        log_format_info = log_data["log_format"]
        return log_format_info

    def get_log_level(self):
        log_data = self.get_log_conf()
        log_level_info = log_data["log_level"]
        return log_level_info
