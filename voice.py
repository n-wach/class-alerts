from twilio.twiml.voice_response import VoiceResponse
from db import ClassMonitor
import logging

logger = logging.getLogger("app.voice")


def route(app):
    @app.route("/voice/open/<monitor_uuid>", methods=["GET", "POST"])
    def voice_open(monitor_uuid):
        monitor = ClassMonitor.query.filter_by(uuid=monitor_uuid).first()
        if monitor is not None:
            logger.debug("Voice open endpoint called for {}".format(monitor))
            name = monitor.class_instance.display_name

            resp = VoiceResponse()
            resp.say("New Class Alerts message. {} has an available spot.".format(name), loop=5)
            resp.hangup()
            return str(resp)
        else:
            logger.debug("Voice open endpoint called with invalid UUID {}".format(monitor_uuid))

            resp = VoiceResponse()
            resp.say("New Class Alerts message.  A class you're monitoring has an available spot.", loop=5)
            resp.hangup()
            return str(resp)
