from flask import Flask, request, jsonify
import threading
import logging
from alert_router import AlertRouter

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('webhook_server')
router = AlertRouter()

@app.route('/webhook/wazuh', methods=['POST'])
def wazuh_webhook():
    alert = request.json
    if not alert:
        return jsonify({"error": "empty payload"}), 400
    
    # Process alert in background to return 200 immediately
    thread = threading.Thread(target=router.route, args=(alert,), daemon=True)
    thread.start()
    return jsonify({"status": "received", "alert_id": alert.get("rule", {}).get("id")}), 200

if __name__ == '__main__':
    logger.info("🚀 بدء خادم SOC Webhook على http://0.0.0.0:5001")
    app.run(host='0.0.0.0', port=5001)
