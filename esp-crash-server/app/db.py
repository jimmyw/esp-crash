"""Raw psycopg2 DB layer. Mechanical move of server.py's DBManager + ldb()
lazy-connection singleton, unchanged."""
import logging
import os

import psycopg2

logger = logging.getLogger(__name__)


class DBManager:
    def __init__(self, database='example', host="db", port=5432, user="root", password=None, password_file=None, sslmode=None):
        if password is None and password_file is not None:
            with open(password_file, 'r') as pf:
                password = pf.read().strip()
        logger.info("Connecting to database %s at %s as user %s", database, host, user)
        self.connection = psycopg2.connect(
            user=user,
            password=password,
            host=host,
            port=port,
            database=database,
            sslmode=sslmode
        )

    def cursor(self):
        self.connection.rollback()
        return self.connection.cursor()

    def commit(self):
        return self.connection.commit()

    def get_data(self, *args):
        cur = self.cursor()
        logger.info("Executing query: %s args: %s", args[0], args[1:])
        cur.execute(*args)
        result = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        return [dict(zip(column_names, row)) for row in result]


conn = None


def ldb():
    """Lazy-initialize and return the database connection."""
    global conn

    if not conn:
        # For testing, print all credentials
        logger.info("Initializing database connection with the following parameters:")
        logger.info("POSTGRES_HOST: %s", os.environ.get('POSTGRES_HOST'))
        logger.info("POSTGRES_USER: %s", os.environ.get('POSTGRES_USER'))
        logger.info("POSTGRES_DB: %s", os.environ.get('POSTGRES_DB'))
        logger.info("POSTGRES_PORT: %s", os.environ.get('POSTGRES_PORT', '5432'))
        logger.info("POSTGRES_PASSWORD_FILE: %s", os.environ.get('POSTGRES_PASSWORD_FILE'))
        postgres_password = os.environ.get('POSTGRES_PASSWORD')
        if postgres_password:
            logger.info("POSTGRES_PASSWORD: [REDACTED length=%d]", len(postgres_password))
        else:
            logger.info("POSTGRES_PASSWORD: [NOT SET]")
        logger.info("POSTGRES_SSLMODE: %s", os.environ.get('POSTGRES_SSLMODE'))

        conn = DBManager(
            password_file=os.environ.get('POSTGRES_PASSWORD_FILE'),
            password=os.environ.get('POSTGRES_PASSWORD'),
            host=os.environ.get('POSTGRES_HOST', ''),
            port=int(os.environ.get('POSTGRES_PORT', '5432')),
            user=os.environ.get('POSTGRES_USER', 'esp-crash'),
            sslmode=os.environ.get('POSTGRES_SSLMODE', 'prefer'),
            database=os.environ.get('POSTGRES_DB', 'esp-crash'),
        )
    return conn
