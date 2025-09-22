import logging
import os
from logging.handlers import TimedRotatingFileHandler


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    green = "\x1b[32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    _format = "[%(name)s] [%(asctime)s] %(levelname)s - [%(filename)s:%(funcName)s:%(lineno)d] %(message)s"

    FORMATS = {
        logging.DEBUG: grey + _format + reset,
        logging.INFO: green + _format + reset,
        logging.WARNING: yellow + _format + reset,
        logging.ERROR: red + _format + reset,
        logging.CRITICAL: bold_red + _format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%d.%m.%y-%H:%M:%S")
        return formatter.format(record)


class PlainFormatter(logging.Formatter):
    """Форматтер для файла без цветовых кодов"""

    _format = "[%(name)s] [%(asctime)s] %(levelname)s - [%(filename)s:%(funcName)s:%(lineno)d] %(message)s"

    def format(self, record):
        formatter = logging.Formatter(self._format, datefmt="%d.%m.%y-%H:%M:%S")
        return formatter.format(record)


def setup_logger(name: str, level: str) -> logging.Logger:
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)

    log_file = os.path.join(log_dir, f"{name}.log")
    file_handler = TimedRotatingFileHandler(
        filename=log_file, when="midnight", interval=1, backupCount=7, encoding="utf-8"
    )
    file_handler.setFormatter(PlainFormatter())
    file_handler.suffix = "%d.%m.%y"
    logger.addHandler(file_handler)

    return logger

