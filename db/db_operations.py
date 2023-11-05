from db.db_connect import connect
import pandas as pd


class db_ops():

    def __init__(self):
        self.conn = connect()
        self.db_cursor = self.conn.cursor()

    def create_db(self):
        try:
            self.db_cursor.execute("DROP TABLE IF EXISTS DGA")
            dga = '''CREATE TABLE DGA(
                       Timestamp VARCHAR(50) NOT NULL,
                       SRC_IP VARCHAR(50),
                       DST_IP VARCHAR(50),
                       URL VARCHAR(500),
                       RESULT VARCHAR(500)
                    )'''
            self.db_cursor.execute("DROP TABLE IF EXISTS PHISH")
            phishing = '''CREATE TABLE PHISH(
                               Timestamp VARCHAR(50) NOT NULL,
                               SRC_IP VARCHAR(50),
                               DST_IP VARCHAR(50),
                               URL VARCHAR(500),
                               RESULT VARCHAR(500)
                            )'''
            self.db_cursor.execute("DROP TABLE IF EXISTS CONN")

            conn_anomaly = '''CREATE TABLE CONN(
                       data VARCHAR(8000) NOT NULL
                    )'''
            self.db_cursor.execute("DROP TABLE IF EXISTS HTTP")

            http_anomaly = '''CREATE TABLE HTTP(
                               data VARCHAR(8000) NOT NULL
                            )'''
            self.db_cursor.execute("DROP TABLE IF EXISTS DNS")

            dns_anomaly = '''CREATE TABLE DNS(
                                      data VARCHAR(8000) NOT NULL
                                   )'''
            tables = [dga, phishing, conn_anomaly, http_anomaly, dns_anomaly]
            for i in tables:
                self.db_cursor.execute(i)
        except Exception as e:
            return {'Success': False, 'Data': e}
        finally:
            return {'Success': True, 'Data': 'Tables created...'}

    def read_db(self, name):
        domains = []
        sql = "SELECT domain FROM "+name + " Where is_deleted = 0"
        try:
            # Execute the SQL command
            self.db_cursor.execute(sql)
            # Fetch all the rows in a list of lists.
            results = self.db_cursor.fetchall()
            for row in results:
                domain = row[0]
                # Now print fetched result
                domains.append(domain)
            self.conn.commit()

        except Exception as e:
            self.conn.rollback()
            return {'Success': False, 'Error': e}
        return domains
        # disconnect from server

    def insert_high_score(self, ip_lst):
        sql = 'INSERT INTO ueba_current_risk (ip_address) VALUES (%s)'
        for ip in ip_lst:
            self.db_cursor.execute(sql, [','.join([ip])])
            # the connection is not autocommitted by default, so we must commit to save our changes
            self.conn.commit()

    def insert_score(self, df):
        sql = "INSERT INTO ueba_risk_score(ip,botnet,dga,phishing,conn,dns,malicious_processes,new_apps,uri_check,http,total) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"


        for i, row in df.iterrows():
            self.db_cursor.execute(sql, tuple(row))
            # the connection is not autocommitted by default, so we must commit to save our changes
            self.conn.commit()

    def insert_db(self, name, data):
        # Preparing SQL query to INSERT a record into the database.
        dga_stmt = (
            "INSERT INTO DGA(Timestamp, SRC_IP, DST_IP, URL, RESULT)"
            "VALUES (%s, %s, %s, %s, %s)"
        )
        phish_stmt = (
            "INSERT INTO PHISH(Timestamp, SRC_IP, DST_IP, URL, RESULT)"
            "VALUES (%s, %s, %s, %s, %s)"
        )
        conn_anomaly = (
            "INSERT INTO CONN(data)"
            "VALUES (%s)"
        )
        dns_anomaly = (
            "INSERT INTO HTTP(data)"
            "VALUES (%s)"
        )
        http_anomaly = (
            "INSERT INTO DNS(data)"
            "VALUES (%s)"
        )
        sql_dict = {'dga': dga_stmt,
                    'phish': phish_stmt,
                    'conn_anomaly': conn_anomaly,
                    'http_anomaly': http_anomaly,
                    'dns_anomaly': dns_anomaly
                    }

        try:
            # Executing the SQL command
            self.db_cursor.execute(sql_dict[name], data,)

            # Commit your changes in the database
            self.conn.commit()
            return {'Success': True, 'Data': 'Data inserted in table '+name}

        except Exception as e:
            # Rolling back in case of error
            print(e)

            self.conn.rollback()
            return {'Success': False, 'Error':e}

        # Closing the connection
        #self.conn.close()

    def fetch_malicious(self, interval=1):
        'Db Queries '
        attack = 'SELECT * FROM `attacks` WHERE `record_timestamp`>= NOW() - INTERVAL '+str(interval)+' DAY'
        conn_anomaly = 'SELECT * FROM `ueba_conn_anomaly` WHERE `record_timestamp`>= NOW() - INTERVAL '+str(interval)+ ' DAY'
        http_anomaly = 'SELECT * FROM `ueba_http_anomaly` WHERE `record_timestamp`>= NOW() - INTERVAL '+str(interval)+ ' DAY'
        dns_anomaly = 'SELECT * FROM `ueba_dns_anomaly` WHERE `record_timestamp`>= NOW() - INTERVAL '+str(10)+' DAY'
        app_check = 'SELECT * FROM `ueba_apcheck` where new_app =1'
        sysmonrnn = 'SELECT * FROM `ueba_malicious_processes` WHERE `record_timestamp`>= NOW() - INTERVAL '+str(40)+' DAY'

        # computer_name = 'UsmanQureshi'
        # cn_to_ip = "SELECT windows_server_ips.ip_address, windows_servers.hostname, windows_server_ips.created_at FROM windows_server_ips\
        # INNER JOIN windows_servers ON (windows_server_ips.windows_server_id = windows_servers.id)\
        # WHERE windows_servers.hostname ='UsmanQureshi' AND windows_servers.is_deleted = 0 AND windows_server_ips.is_deleted = 0\
        # ORDER BY windows_server_ips.created_at DESC"

        attacks_df = pd.read_sql(sql=attack, con=self.conn)
        conn_anomaly_df = pd.read_sql(sql=conn_anomaly, con=self.conn)
        http_anomaly_df = pd.read_sql(sql=http_anomaly, con=self.conn)
        dns_anomaly_df = pd.read_sql(sql=dns_anomaly, con=self.conn)
        app_check_df = pd.read_sql(sql=app_check, con=self.conn)
        sysmonrnn_df = pd.read_sql(sql=sysmonrnn, con=self.conn)

        return attacks_df, conn_anomaly_df, http_anomaly_df, dns_anomaly_df, sysmonrnn_df, app_check_df

    def fetch_risk_table(self):
        sql = 'Select * FROM `ueba_risk_score` WHERE `created_at`>= NOW() - INTERVAL '+str(1)+ ' DAY'
        risk_table = pd.read_sql(sql=sql, con=self.conn)
        return risk_table


if __name__ =='__main__':
    db_cons = db_ops()
    #db_cons.create_db()
    print(db_cons.read_db(name='dga_whitelist'))
    res = db_cons.risk_calc()

