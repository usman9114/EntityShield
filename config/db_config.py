from configparser import ConfigParser
from os.path import join
import pandas as pd
from db.db_connect import connect

def read_db_config(filename= join('local.ini'), section='mysql',multitenant_flag=False):
    """ Read database configuration file and return a dictionary object
    :param filename: name of the configuration file
    :param section: section of database configuration
    :return: a dictionary of database parameters
    """
    # create parser and read ini configuration file
    parser = ConfigParser()
    parser.read(filename)

    # get section, default to mysql
    db = {}
    if multitenant_flag:
        multitenant = pd.read_sql('Select elastic_ip, elastic_port,mysql_host_ip, mysql_username, mysql_password,' \
                                  ' my_sql_port from client_configurations where id ={}'.format(1),
                                  con=connect(filename=join('properties.ini'))).to_dict()
        db['host'] = multitenant['mysql_host_ip'][0]
        db['user'] = multitenant['mysql_username'][0]
        db['password'] = multitenant['mysql_password'][0]

    elif parser.has_section(section):
        items = parser.items(section)
        for item in items:
            db[item[0]] = item[1]
    else:
        raise Exception('{0} not found in the {1} file'.format(section, filename))

    return db
if __name__ == '__main__':
    print(read_db_config())
