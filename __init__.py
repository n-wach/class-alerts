from app import app

if __name__ == "__main__":
    import logging
    from logging.handlers import TimedRotatingFileHandler

    handler = TimedRotatingFileHandler("/logs/Alerts.log", when="midnight")
    logging.root.addHandler(handler)

    logging.root.info("Running app...")

    app.run(debug=True, use_reloader=False)
