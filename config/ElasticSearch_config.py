from configparser import ConfigParser
from os.path import join
import pandas as pd
from db.db_connect import connect

def read_elastic_config(filename= join('local.ini'), section='elastic',multitenant_flag=False):
    """ Read database configuration file and return a dictionary object
    :param filename: name of the configuration file
    :param section: section of database configuration
    :return: a dictionary of database parameters
    """
    elastic = {}
    if multitenant_flag:
        multitenant = pd.read_sql('Select elastic_ip, elastic_port,mysql_host_ip, mysql_username, mysql_password,' \
                                  ' my_sql_port from client_configurations where id ={}'.format(1),
                                  con=connect(filename=join('properties.ini'))).to_dict()
        elastic['host'] = multitenant['elastic_ip'][0]
        elastic['port'] = multitenant['elastic_port'][0]
    else:
        # create parser and read ini configuration file
        parser = ConfigParser()
        parser.read(filename)

        # get section, default to mysql
        elastic = {}
        if parser.has_section(section):
            items = parser.items(section)
            for item in items:
                elastic[item[0]] = item[1]
        else:
            raise Exception('{0} not found in the {1} file'.format(section, filename))

    return elastic
if __name__ == '__main__':
    print(read_elastic_config())
