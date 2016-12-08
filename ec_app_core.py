#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

from ec_utilities import *

import threading
import psutil

class EcAppCore(threading.Thread):
    """
    Root class of the application core instance. Actual applications must subclass this.
    """

    def __init__(self):
        """
        Perform the following housekeeping tasks:

        * Start the connection pool.
        * Test the DB connection by storing a startup message in `TB_EC_MSG`.
        * Start the health check thread.
        """
        super().__init__(daemon=True)

        # logger
        self.m_logger = logging.getLogger('AppCore')

        # connecion pool init
        try:
            self.m_connectionPool = EcConnectionPool.getNew()
        except Exception as e:
            self.m_logger.warning('Unable to start Connection pool: {0}-{1}'.format(
                type(e).__name__, repr(e)
            ))
            raise

        # Add a record to TB_EC_MSG, thus testing the db connection
        l_conn = self.m_connectionPool.getconn('DB Connection test in EcAppCore.__init__()')
        l_cursor = l_conn.cursor()
        try:
            l_cursor.execute("""
                insert into "TB_EC_MSG"(
                    "ST_NAME",
                    "ST_LEVEL",
                    "ST_MODULE",
                    "ST_FILENAME",
                    "ST_FUNCTION",
                    "N_LINE",
                    "TX_MSG"
                )
                values(%s, %s, %s, %s, %s, %s, %s);
            """, (
                'xxx',
                'XXX',
                'ec_app_core',
                './ec_app_core.py',
                '__init__',
                0,
                '{0} v. {1} starting'.format(
                    EcAppParam.gcm_appName,
                    EcAppParam.gcm_appVersion
                )
            ))
            l_conn.commit()
        except psycopg2.IntegrityError as e:
            self.m_logger.warning('TB_EC_MSG insert failure - Integrity error: {0}-{1}'.format(
                type(e).__name__,
                repr(e)
            ))
            raise
        except Exception as e:
            self.m_logger.warning('TB_EC_MSG insert failure: {0}-{1}'.format(
                type(e).__name__,
                repr(e)
            ))
            raise

        l_cursor.close()
        self.m_connectionPool.putconn(l_conn)
        self.m_logger.info('Sucessuful TB_EC_MSG insert - The DB appears to be working')

        # health check counter
        self.m_hcCounter = 0

        # starts the refresh thread
        self.start()

    #: Connecion pool access
    def getConnectionPool(self):
        return self.m_connectionPool

    #: Main application entry point - App response to an HTTP request
    def getResponse(self, p_requestHandler):
        return '<p style="color:red;">YOU SHOULD NOT BE SEEING THIS - EcAppCore.getResponse()</p>'

    # ------------------------- Access to i18n strings -----------------------------------------------------------------
    def get_user_string(self, p_context, p_stringId):
        """
        Access to the i18n table (:any:`EcAppParam.i18n`) with default values and error reporting.

        By convention, `p_context['z']` = UI language throughout the application. If no `'z'` key exist in
        `p_context``, `'en'` (English) is used by default.

        :param p_context: Context dictionary from whitch to extract the language information.
        :param p_stringId: The key to a UI string
        :return: The requested string
        """

        try:
            l_lang = p_context['z']
        except KeyError:
            self.m_logger.warning('No language information in p_context: {0}'.format(repr(p_context)))
            l_lang = 'en'

        try:
            l_string = EcAppParam.i18n(l_lang + '-' + p_stringId)
        except KeyError:
            l_string = 'WARNING UI string for key [] not defined - YOU SHOULD NOT BE SEEING THIS'.format(p_stringId)
            self.m_logger.warning('UI string for key [] not defined'.format(p_stringId))

        return l_string

    # ------------------------- System health test ---------------------------------------------------------------------
    def check_system_health(self):
        """
        Checks memory usage and issues a warning if over 75%.

        Every tenth time (once in 5 min.) a full recording of system parameters is made through
        `psutil <https://pythonhosted.org/psutil/>`_ and stored in `TB_MSG`.
        """
        l_mem = psutil.virtual_memory()

        self.m_logger.info('System Health Check - Available RAM: {0} Mb ({1} % usage)'.format(
            l_mem.available / (1024 * 1024), l_mem.percent))

        if l_mem.percent > 75:
            self.m_logger.warning('System Health Check ALERT - Available RAM: {0} Mb ({1} % usage)'.format(
                l_mem.available / (1024 * 1024), l_mem.percent))

        # full system resource log every 5 minutes
        if self.m_hcCounter % 10 == 0:
            l_cpu = psutil.cpu_times()
            l_swap = psutil.swap_memory()
            l_diskRoot = psutil.disk_usage('/')
            l_net = psutil.net_io_counters()
            l_processCount = len(psutil.pids())

            # log message in TB_EC_MSG
            l_conn = psycopg2.connect(
                host=EcAppParam.gcm_dbServer,
                database=EcAppParam.gcm_dbDatabase,
                user=EcAppParam.gcm_dbUser,
                password=EcAppParam.gcm_dbPassword
            )
            l_cursor = l_conn.cursor()
            try:
                l_cursor.execute("""
                    insert into "TB_EC_MSG"(
                        "ST_NAME",
                        "ST_LEVEL",
                        "ST_MODULE",
                        "ST_FILENAME",
                        "ST_FUNCTION",
                        "N_LINE",
                        "TX_MSG"
                    )
                    values(%s, %s, %s, %s, %s, %s, %s);
                """, (
                    'xxx',
                    'XXX',
                    'ec_app_core',
                    './ec_app_core.py',
                    'check_system_health',
                    0,
                    'MEM: {0}/CPU: {1}/SWAP: {2}/DISK(root): {3}/NET: {4}/PROCESSES: {5}'.format(
                        l_mem, l_cpu, l_swap, l_diskRoot, l_net, l_processCount
                    )
                ))
                l_conn.commit()
            except Exception as e:
                EcMailer.sendMail('TB_EC_MSG insert failure: {0}-{1}'.format(
                    type(e).__name__,
                    repr(e)
                ), 'Sent from EcConsoleFormatter')
                raise

            l_cursor.close()
            l_conn.close()

        self.m_hcCounter += 1

    #: System health check and app monitoring thread
    def run(self):
        self.m_logger.info('System health check thread started ...')
        while True:
            # sleeps for 30 seconds
            time.sleep(30)

            # system health check
            self.check_system_health()

            l_fLogName = re.sub('\.csv', '.all_connections', EcAppParam.gcm_logFile)
            l_fLog = open(l_fLogName, 'w')
            l_fLog.write(self.m_connectionPool.connectionReport())
            l_fLog.close()

