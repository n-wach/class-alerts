from app import app

if __name__ == "__main__":
    import logging
    from logging.handlers import TimedRotatingFileHandler

    for h in logging.root.handlers[:]:
        logging.root.removeHandler(h)

    logger = logging.getLogger("app")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    file_logger = TimedRotatingFileHandler("logs/Alerts.log", when="midnight")
    file_logger.setFormatter(formatter)
    file_logger.setLevel(logging.DEBUG)
    logger.addHandler(file_logger)

    console_logger = logging.StreamHandler()
    console_logger.setFormatter(formatter)
    console_logger.setLevel(logging.DEBUG)
    logger.addHandler(console_logger)

    logger.info("Running app...")

    app.run(debug=True, use_reloader=False)
