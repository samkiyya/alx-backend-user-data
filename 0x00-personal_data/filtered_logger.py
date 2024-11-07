#!/usr/bin/env python3
"""
Module for handling and securely logging Personal Data from a database.
"""

from typing import List
import re
import logging
import os
import mysql.connector
from mysql.connector import MySQLConnection

# Define the fields that contain PII
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Returns an obfuscated log message where specified fields are replaced by the redaction string.
    
    Args:
        fields (List[str]): List of strings representing PII fields to obfuscate.
        redaction (str): The string to replace PII field values with.
        message (str): The original log message that may contain PII.
        separator (str): The delimiter used to separate fields in the message.
    
    Returns:
        str: The obfuscated log message.
    """
    for f in fields:
        message = re.sub(f'{f}=.*?{separator}', f'{f}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """
    Sets up and returns a Logger object configured to use a RedactingFormatter for PII fields.
    
    Returns:
        logging.Logger: Configured logger instance for logging user data.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> MySQLConnection:
    """
    Establishes and returns a connector to a MySQL database using credentials from environment variables.
    
    Returns:
        MySQLConnection: A MySQLConnection object for interacting with the MySQL database.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")

    return mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )


def main():
    """
    Retrieves and logs rows from the 'users' table in a MySQL database, filtering sensitive PII fields.
    
    This function connects to a MySQL database using get_db(), then queries all rows from the
    'users' table. Each row is formatted and logged with PII fields obfuscated.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cursor.description]

    logger = get_logger()

    for row in cursor:
        str_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(row, field_names))
        logger.info(str_row.strip())

    cursor.close()
    db.close()


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class for obfuscating sensitive fields in log messages.
    
    Attributes:
        REDACTION (str): The string to replace sensitive field values with.
        FORMAT (str): The log message format.
        SEPARATOR (str): The delimiter for separating log message fields.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes a RedactingFormatter instance.
        
        Args:
            fields (List[str]): List of strings representing PII fields to obfuscate.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Obfuscates sensitive fields in the log record message before formatting.
        
        Args:
            record (logging.LogRecord): The log record containing the message to format.
        
        Returns:
            str: The formatted and obfuscated log message.
        """
        record.msg = filter_datum(self.fields, self.REDACTION, record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


if __name__ == '__main__':
    main()
