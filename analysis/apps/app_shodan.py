from datetime import datetime
from flask import Flask, jsonify, request, Blueprint

from settings import *
from cores.vt_intelligence import IntelligenceHandler
from cores.vt_files import FileHandler
from utils.utils_log import LogFactory

logger = LogFactory.get_log("audit")

shodan_app = Blueprint("shodan", __name__)

