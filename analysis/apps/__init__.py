from apps.app_config import config_app
from apps.app_shodan import shodan_app
from apps.app_vt import files_app, intelligence_app

bp_config = config_app
bp_shodan = shodan_app
bp_files = files_app
bp_intelligence = intelligence_app