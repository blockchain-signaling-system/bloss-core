import json
import requests

from flask import Flask, request, jsonify
from flask_restful import abort

from configuration import Configuration
from logger import Logger
from pollen.attack_reporting import AttackReporting

logger = Logger("Stalk")

app = Flask(__name__)
config = Configuration()
attack_reporting = AttackReporting(config)
stalk_controller = None


@app.route("/api/v1.0/mitigate", methods=['POST'])
def mitigate():
    if not request.json:
        abort(400, message="No attack reports provided")
    json_data = None
    try:
        logger.info("[STALK/mitigate (first try block) request.json ")
        logger.info(request.json)
        json_data = json.loads(request.get_json(force=True))
        logger.info("[STALK/mitigate called from within bloss")
        logger.info("[STALK/mitigate (first try block)]")
        logger.info(json_data)
        logger.info(json_data.keys())
        attack_report = (attack_reporting.parse_attack_report_message(json_data))
    except Exception as e:
        logger.info("[STALK/mitigate] (first try block) Could not load JSON from your request;")
        logger.info(e)
    if json_data is None:
        try:
            logger.info("[STALK/mitigate (second try block) request.json ")
            logger.info(request.json)
            json_data = request.json
            logger.info(json_data.keys())
            # json.dumps(obj): Serialize obj to a JSON formatted str
            # json.loads(s): Deserialize s (a str instance containing a JSON document) to a Python object
            logger.info("[STALK/mitigate (second try block) type(json_date):{}".format(type(json_data)))
            if json_data is None:
                logger.info("[STALK/mitigate (second try block): request.get_json() returned NONE ]")
            logger.info(json_data)
            attack_report = attack_reporting.parse_attack_report_from_node(json_data)
            logger.info(attack_report)
        except Exception as e:
            logger.info("[STALK/mitigate](second try block) Could not load JSON from your request;")
            logger.info(e)
            json_data = request.json
    logger.info("[STALK/mitigate]attack_report = (attack_reporting.parse_attack_report_message(json_data))")
    logger.info(attack_report)
    logger.info("[STALK/mitigate]attack_report:".format(attack_report))
    if stalk_controller is not None:
        stalk_controller.block_attackers(attack_report)
    else:
        logger.error("Stalk controller not configured")
        return "Stalk controller not configured", 500
    return "Accepted attackers for blocking", 202


@app.route("/api/v1.0/test", methods=['POST'])
def test():
    if request.is_json:
        data = request.get_json()
        return jsonify(data)
    else:
        return jsonify(status="Request was not JSON")
