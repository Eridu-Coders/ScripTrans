#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

from ec_utilities import *

import threading
import psutil

class EcAppCore(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

        # logger
        self.m_logger = logging.getLogger('AppCore')

        # connecion pool init
        self.m_connectionPool = EcConnectionPool(
            EcAppParam.gcm_connectionPoolMinCount,
            EcAppParam.gcm_connectionPoolMaxCount,
            host=EcAppParam.gcm_dbServer,
            database=EcAppParam.gcm_dbDatabase,
            user=EcAppParam.gcm_dbUser,
            password=EcAppParam.gcm_dbPassword
        )

        # Add a record to TB_EC_LOG, thus testing the db connection
        l_conn = self.m_connectionPool.getconn()
        l_cursor = l_conn.cursor()
        try:
            l_cursor.execute("""
                insert into "TB_EC_LOG"("TERMINAL_ID", "ST_IP")
                values('{0}', '{1}');
            """.format(
                'App Start',
                '{0} v. {1}'.format(
                    EcAppParam.gcm_appName,
                    EcAppParam.gcm_appVersion
                )
            ))
            l_conn.commit()
        except psycopg2.IntegrityError as e:
            self.m_logger.warning('TB_EC_LOG insert failure - Integrity error: {0}-{1}'.format(
                type(e).__name__,
                repr(e)
            ))
            raise
        except Exception as e:
            self.m_logger.warning('TB_EC_LOG insert failure: {0}-{1}'.format(
                type(e).__name__,
                repr(e)
            ))
            raise

        self.m_connectionPool.putconn(l_conn)
        self.m_logger.info('Sucessuful TB_EC_LOG insert - The DB appears to be working')

        # starts the refresh thread
        self.start()

    # connecion pool access
    def getConnectionPool(self):
        return self.m_connectionPool

    #def getResponse(self, p_previousContext, p_context, p_dbConnectionPool, p_urlPath, p_noJSPath, p_terminalID):
    #    pass
    def getResponse(self, p_requestHandler):
        pass

    # ------------------------- Access to i18n strings -----------------------------------------------------------------
    @staticmethod
    def get_user_string(p_context, p_stringId):
        # p_context['z'] = UI language
        # g_userStrings = dict of strings defined in ec_app_params.py.
        return EcAppParam.i18n(p_context['z'] + '-' + p_stringId)

    # ------------------------- System health test ---------------------------------------------------------------------
    def check_system_health(self):
        """
        Checks memory usage and issues a warning if over 75%.
        """
        l_mem = psutil.virtual_memory()

        self.m_logger.info('System Health Check - Available RAM: {0} Mb ({1} % usage)'.format(
            l_mem.available / (1024 * 1024), l_mem.percent))

        if l_mem.percent > 75:
            self.m_logger.warning('System Health Check ALERT - Available RAM: {0} Mb ({1} % usage)'.format(
                l_mem.available / (1024 * 1024), l_mem.percent))

    # refresher thread
    def run(self):
        self.m_logger.info('System health check thread started ...')
        while True:
            # sleeps for 30 seconds
            time.sleep(30)

            # system health check
            self.check_system_health()
