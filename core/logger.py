# core/logger.py
import logging
import os
from datetime import datetime
import pytz

def setup_logger():
    logger = logging.getLogger("PentestPal")
    logger.setLevel(logging.INFO)
    
    # Hardcode the log directory
    log_dir = r"logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, "pentest.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    
    # Formatter with local timezone (PDT)
    local_tz = pytz.timezone("America/Los_Angeles")
    class LocalTimeFormatter(logging.Formatter):
        def formatTime(self, record, datefmt=None):
            dt = datetime.fromtimestamp(record.created, tz=pytz.utc).astimezone(local_tz)
            return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    
    formatter = LocalTimeFormatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    
    # Clear existing handlers and add new one
    logger.handlers = []
    logger.addHandler(file_handler)
    
    # Add session start marker with 1 blank line before
    logger.info("********** SESSION STARTED **********")
    file_handler.flush()
    
    return logger