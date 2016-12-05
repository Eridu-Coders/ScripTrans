#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

from ec_app_core import *
from ec_request_handler import *

import random
import sys
from socketserver import ThreadingMixIn

# Multi-threaded HTTP server according to https://pymotw.com/2/BaseHTTPServer/index.html#module-BaseHTTPServer
class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """Handles requests in a separate thread each."""

class StartApp:
    """
    This is a simple wrapper around the function which starts the application. Everything is static.
    """

    @classmethod
    def startScripTrans(cls):
        """
        The actual entry point, called from ``if __name__ == "__main__":``. Does the following:

        #. Initialises the mailer (:any:`EcMailer.initMailer`)
        #. Initialises the logging system (:any:`EcLogger.logInit`)
        """
        print('ScripTrans server starting ...')

        # random generator init
        random.seed()

        # mailer init
        EcMailer.initMailer()

        # logging system init
        try:
            EcLogger.logInit()
        except Exception as e:
            EcMailer.sendMail('Failed to initialize EcLogger', str(e))

        try:
            # instantiate the app (and the connection pool within it)
            l_app = EcAppCore()
        except Exception as e:
            EcLogger.cm_logger.critical('App crashed. Error: {0}'.format(repr(e)))
            sys.exit(0)

        try:
            # python http server init
            l_httpd = ThreadedHTTPServer(("", EcAppParam.gcm_httpPort), EcRequestHandler)
        except Exception as e:
            EcLogger.cm_logger.critical('Cannot start server at [{0}:{1}]. Error: {2}-{3}'.format(
                EcAppParam.gcm_appDomain,
                EcAppParam.gcm_httpPort,
                type(e).__name__, repr(e)
            ))
            sys.exit(0)

        EcLogger.rootLogger().info('gcm_appName    : ' + EcAppParam.gcm_appName)
        EcLogger.rootLogger().info('gcm_appVersion : ' + EcAppParam.gcm_appVersion)
        EcLogger.rootLogger().info('gcm_appTitle   : ' + EcAppParam.gcm_appTitle)

        # final success message (sends an e-mail message because it is a warning)
        EcLogger.cm_logger.warning('Server up and running at [{0}:{1}]'
                                   .format(EcAppParam.gcm_appDomain, str(EcAppParam.gcm_httpPort)))

        try:
            # start server main loop
            l_httpd.serve_forever()
        except Exception as e:
            EcLogger.cm_logger.critical('App crashed. Error: {0}-{1}'.format(type(e).__name__, repr(e)))

# ---------------------------------------------------- Main section ----------------------------------------------------
if __name__ == "__main__":
    StartApp.startScripTrans()
