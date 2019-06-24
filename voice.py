from twilio.twiml.voice_response import VoiceResponse


def route(app):
    @app.route("/voice/open", methods=["GET", "POST"])
    def voice_open():
        resp = VoiceResponse()
        resp.say("A class you're monitoring on Class Alerts has an available spot.", loop=5)
        resp.hangup()
        return str(resp)
