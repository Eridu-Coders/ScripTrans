#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

from ec_utilities import *

import random

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

        # final success message
        EcLogger.rootLogger().warning('Server up and running at [{0}:{1}]'
            .format(EcAppParam.gcm_appDomain, str(EcAppParam.gcm_httpPort)))

# ---------------------------------------------------- Main section ----------------------------------------------------
if __name__ == "__main__":
    StartApp.startScripTrans()
