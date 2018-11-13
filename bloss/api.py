import json

from flask import Flask, request, jsonify, Response
from flask_restful import abort

from configuration import Configuration
from pollen.attack_reporting import AttackReporting

from logger import Logger

logger = Logger("BloSS")

app = Flask(__name__)
pollen_blockchain = None
config = Configuration()
attack_reporting = AttackReporting(config)


@app.route('/api/v1.0/report', methods=['POST'])
def report():
    if not request.json:
        abort(400, message="No attack reports provided")
    json_data = None
    attack_reports = []
    try:
        json_data = json.loads(request.get_json(force=True))
        for message in json_data:
            attack_reports.append(attack_reporting.parse_attack_report_message(message))
    except Exception as e:
        logger.info(e)

    if json_data is None:
        try:
            json_data = request.json
            logger.info("[STALK/mitigate (second try block) type(json_date):{}".format(type(json_data)))
            attack_report = attack_reporting.parse_attack_report_from_node(json_data)
            attack_reports.append(attack_report)
        except Exception as e:
            logger.info(e)
    logger.info(attack_reports)
    try:
        pollen_blockchain.report_attackers(attack_reports)
    except:
        return "Failed to report attackers to blockchain", 500
    return "Successfully reported attackers to blockchain", 201


@app.route('/api/v1.0/set_blocked', methods=['POST'])
def set_blocked():
    if not request.json:
        abort(400, message="No hash provided.")
    json_data = json.loads(request.get_json(force=True))
    try:
        pollen_blockchain.set_blocked(json_data['hash'])
    except:
        return "Failed to mark attack report hash as blocked", 500
    return "Successfully marked attack report hash as blocked", 201

