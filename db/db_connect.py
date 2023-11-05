from mysql.connector import MySQLConnection, Error
from config.db_config import read_db_config
from os.path import join


def connect(filename = join('db_config.ini')):
    """ Connect to MySQL database """
    db_config = read_db_config(filename)
    conn = None
    try:
        print('Connecting to MySQL database...')
        conn = MySQLConnection(**db_config)

        if conn.is_connected():
            print('Connection established.')
        else:
            print('Connection failed.')

    except Error as error:
        print(error)

    # finally:
    #     if conn is not None and conn.is_connected():
    #         conn.close()
    #         print('Connection closed.')
    return conn


if __name__ == '__main__':
    connect()