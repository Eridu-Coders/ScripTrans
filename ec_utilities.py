#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

from ec_app_param import *

import logging
import re
import email
import datetime
import time
import pytz
import smtplib
import psycopg2.pool
import threading

# -------------------------------------- Logging Set-up ----------------------------------------------------------------
class EcLogger(logging.Logger):
    """
    Custom logging class (see `the python doc re. logging <https://docs.python.org/3.5/library/logging.html>`_)
    """

    #: static variable containing the root logger.
    cm_logger = None

    @classmethod
    def rootLogger(cls):
        """
        Access to the root logger (used only in the startup sequence)
        :return: the root logger
        """
        return cls.cm_logger

    def __init__(self, p_name=None, p_level=logging.NOTSET):
        """
        Customm logger init. Handles the logger name (app name + '.logger name') and sets
        the logging level according to :any:`gcm_verboseModeOn` and :any:`gcm_debugModeOn`.

        :param str p_name: Name to append to the logger name (+ '.p_name'). If ``None`` then the logger name is just the app name (``gcm_appName``)
        :param p_level: optional level setting (never used)
        :type p_level: `logging level <https://docs.python.org/3.5/library/logging.html#logging-levels>`_

        """
        if p_name is None:
            super().__init__(EcAppParam.gcm_appName, p_level)
        else:
            super().__init__(EcAppParam.gcm_appName + '.' + p_name, p_level)

        if EcAppParam.gcm_verboseModeOn:
            self.setLevel(logging.INFO)
        if EcAppParam.gcm_debugModeOn:
            self.setLevel(logging.DEBUG)

    @classmethod
    def logInit(cls):
        """
        Initializes the logging system by creating the root logger + 2 subclasses of :py:class:`logging.Formatter`
        to handle:

        * the in-console display of log messages.
        * their storage into a CSV file (path given in :any:`gcm_logFile`).

        Only INFO level messages and above are displayed on screen (if :any:`gcm_verboseModeOn` is set).
        DEBUG level messages, if any, are sent to the CSV file.
        """
        # Creates the column headers for the CSV log file
        l_fLog = open(EcAppParam.gcm_logFile, 'w')
        l_fLog.write('LOGGER_NAME;TIME;LEVEL;MODULE;FILE;FUNCTION;LINE;MESSAGE\n')
        l_fLog.close()

        # registers the EcLogger class with the logging system
        logging.setLoggerClass(EcLogger)

        # Create the main logger
        cls.cm_logger = logging.getLogger()

        # One handler for the console (only up to INFO messages) and another for the CSV file (everything)
        l_handlerConsole = logging.StreamHandler()
        l_handlerFile = logging.FileHandler(EcAppParam.gcm_logFile, mode='a')

        # Custom Formatter for the CSV file --> eliminates multiple spaces (and \r\n)
        class EcCsvFormatter(logging.Formatter):
            def format(self, p_record):
                l_record = logging.LogRecord(
                    p_record.name,
                    p_record.levelno,
                    p_record.pathname,
                    p_record.lineno,
                    re.sub('"', '""', p_record.msg),
                    # message arguments are not allowed here
                    None,
                    # p_record.args,
                    p_record.exc_info,
                    p_record.funcName,
                    p_record.stack_info,
                )

                return re.sub('\s+', ' ', super().format(l_record))

        # Custom Formatter for the console --> send mail if warning or worse
        class EcConsoleFormatter(logging.Formatter):
            def format(self, p_record):
                l_formatted = super().format(p_record)

                if p_record.levelno >= logging.WARNING:
                    EcMailer.sendMail(
                        '{0}-{1}[{2}]/{3}'.format(
                            p_record.levelname,
                            p_record.module,
                            p_record.lineno,
                            p_record.funcName),
                        l_formatted
                    )

                return l_formatted

        # Install formatters
        l_handlerConsole.setFormatter(EcConsoleFormatter('ECL:%(levelname)s:%(name)s:%(message)s'))
        l_handlerFile.setFormatter(EcCsvFormatter('"%(name)s";"%(asctime)s";"%(levelname)s";"%(module)s";' +
                                                  '"%(filename)s";"%(funcName)s";%(lineno)d;"%(message)s"'))

        # If verbose mode on, both handlers receive messages up to INFO
        if EcAppParam.gcm_verboseModeOn:
            cls.cm_logger.setLevel(logging.INFO)
            l_handlerConsole.setLevel(logging.INFO)
            l_handlerFile.setLevel(logging.INFO)

        # If debug mode is on, then the console stays as it is but the CSV file now receives everything
        if EcAppParam.gcm_debugModeOn:
            cls.cm_logger.setLevel(logging.DEBUG)
            l_handlerFile.setLevel(logging.DEBUG)

        # Install the handlers
        cls.cm_logger.addHandler(l_handlerConsole)
        cls.cm_logger.addHandler(l_handlerFile)

        # Start-up Messages
        cls.cm_logger.info('-->> Start logging')
        cls.cm_logger.debug('-->> Start logging')


# -------------------------------------- e-mail messages sending -------------------------------------------------------
class EcMailer(threading.Thread):
    """
    Sends an e-mail through smtp. Can handle the following servers:

    * Amazon AWS SES (TLS auth)
    * Gmail (TLS auth)
    * Ordinary SMTP without authentication.

    The type of server is determined by :any:`LocalParam.gcm_amazonSmtp` (true for AWS) and
    :any:`LocalParam.gcm_gmailSmtp` (true for Gmail)

    For an Amazon SES howto, see:
    `this blog page <http://blog.noenieto.com/blog/html/2012/06/18/using_amazon_ses_with_your_python_applications.html>`_

    For a Gmail TLS howto, see:
    `this page <http://stackabuse.com/how-to-send-emails-with-gmail-using-python/>`_
    """

    #: List of previously sent messages with timestamps, to avoid sending too many (min. 5min. deep).
    cm_sendMailGovernor = None

    #: Concurrency management lock to control access to :any:`cm_sendMailGovernor` This is necessary
    #: because each mail sending operation is executed asynchronously in its own thread
    cm_mutexGovernor = None

    #: Concurrency management lock to control access to the log files (see :any:`sendMail`). This is necessary
    #: because each mail sending operation is executed asynchronously in its own thread
    cm_mutexFiles = None

    @classmethod
    def initMailer(cls):
        """
        Mail system intialization. Creates an empty :any:`cm_sendMailGovernor` and the associated
        Mutexes to allow critical section protection.
        """
        cls.cm_sendMailGovernor = dict()
        cls.cm_mutexGovernor = threading.Lock()
        cls.cm_mutexFiles = threading.Lock()

    @classmethod
    def sendMail(cls, p_subject, p_message):
        """
        Sends an e-mail message asynchronously (each call executed in its own thread) to avoid
        blocking the main application flow while waiting for the SMTP server to respond.

        Every sent message goes into a text file
        (same path as :any:`EcAppParam.gcm_logFile` but with 'all_msg' at the end instead of 'csv')

        Ensures that no more than 10 message with the same subject are sent every 5 minutes
        (using :any:`cm_sendMailGovernor`) Beyond this, the messages are not sent but stored in the overflow file
        (same path as :any:`EcAppParam.gcm_logFile` but with 'overflow_msg' at the end instead of 'csv')

        Errors encountered during processing are stored in a dedicated file (same path as
        :any:`EcAppParam.gcm_logFile` but with 'smtp_error' at the end instead of 'csv')
        This file is in CSV format so that it can be merged with the main CSV log file.
        Yet another file receives the messages which could not ne sent due to these errors (same path as
        :any:`EcAppParam.gcm_logFile` but with 'rejected_msg' at the end instead of 'csv')

        All these files are appended to (open mode ``'a'``) Nothing is ever removed from them. Any
        write access to them is protected by a mutex because of the asynchronous nature of the operations (several
        e-mail messages may be in the process of being sent in parallel)

        :param p_subject: Message subject.
        :param p_message: Message body.
        """
        l_thread = EcMailer(p_subject, p_message)
        l_thread.start()

    def __init__(self, p_subject, p_message):
        """
        preparing the thread to be launched (by :any:`sendMail`)

        :param p_subject: same as in :any:`sendMail`
        :param p_message: same as in :any:`sendMail`
        """
        self.m_subject = p_subject
        self.m_message = p_message

        super().__init__()

    def run(self):
        """
        Actual e-mail sending process (executed in separate thread)
        """

        # message context with headers and body
        l_message = """From: {0}
            To: {1}
            Date: {2}
            Subject: {3}

            {4}
        """.format(
            EcAppParam.gcm_mailSender,
            ', '.join(EcAppParam.gcm_mailRecipients),
            email.utils.format_datetime(datetime.datetime.now(tz=pytz.utc)),
            self.m_subject,
            self.m_message
        )

        # removes spaces at the begining of lines
        l_message = re.sub('^[ \t\r\f\v]+', '', l_message, flags=re.MULTILINE)

        # limitation of email sent
        EcMailer.cm_mutexGovernor.acquire()
        #### cm_sendMailGovernor CRITICAL SECTION START ######
        l_now = time.time()
        try:
            # the list of all UNIX timestamps when this subject was sent in the previous 5 min at least
            l_thisSubjectHistory = EcMailer.cm_sendMailGovernor[self.m_subject]
        except KeyError:
            l_thisSubjectHistory = [l_now]

        l_thisSubjectHistory.append(l_now)

        l_thisSubjectHistoryNew = list()
        l_count = 0
        for l_pastsend in l_thisSubjectHistory:
            if l_now - l_pastsend < 5*60:
                l_count += 1
                l_thisSubjectHistoryNew.append(l_pastsend)

        EcMailer.cm_sendMailGovernor[self.m_subject] = l_thisSubjectHistoryNew
        #### cm_sendMailGovernor CRITICAL SECTION END ######
        EcMailer.cm_mutexGovernor.release()

        # maximum : 10 with the same subject every 5 minutes
        if l_count > 10:
            # overflow stored the message in a separate file
            EcMailer.cm_mutexFiles.acquire()
            l_fLog = open(re.sub('\.csv', '.overflow_msg', EcAppParam.gcm_logFile), 'a')
            l_fLog.write('>>>>>>>\n' + l_message)
            l_fLog.close()
            EcMailer.cm_mutexFiles.release()
            return

        # all messages
        l_fLogName = re.sub('\.csv', '.all_msg', EcAppParam.gcm_logFile)
        EcMailer.cm_mutexFiles.acquire()
        l_fLog = open(l_fLogName, 'a')
        l_fLog.write('>>>>>>>\n' + l_message)
        l_fLog.close()
        EcMailer.cm_mutexFiles.release()

        # numeric value indicating the steps in the authentication process, for debug purposes
        l_stepPassed = 0
        try:
            if EcAppParam.gcm_amazonSmtp:
                # Amazon AWS/SES

                # smtp client init
                l_smtpObj = smtplib.SMTP(
                    host=EcAppParam.gcm_smtpServer,
                    port=587,
                    timeout=10)
                l_stepPassed = 101

                # initialize TLS connection
                l_smtpObj.starttls()
                l_stepPassed = 102
                l_smtpObj.ehlo()
                l_stepPassed = 103

                # authentication
                l_smtpObj.login(EcAppParam.gcm_sesUserName, EcAppParam.gcm_sesPassword)
                l_stepPassed = 104
            elif EcAppParam.gcm_gmailSmtp:
                # Gmail / TLS authentication

                # smtp client init
                l_smtpObj = smtplib.SMTP(EcAppParam.gcm_smtpServer, 587)
                l_stepPassed = 201

                # initialize TLS connection
                l_smtpObj.starttls()
                l_stepPassed = 202
                l_smtpObj.ehlo()
                l_stepPassed = 203

                # authentication
                l_smtpObj.login(EcAppParam.gcm_mailSender, EcAppParam.gcm_mailSenderPassword)
                l_stepPassed = 204
            else:
                l_smtpObj = smtplib.SMTP(EcAppParam.gcm_smtpServer)

            # sending message
            l_smtpObj.sendmail(EcAppParam.gcm_mailSender, EcAppParam.gcm_mailRecipients, l_message)
            l_stepPassed = 99

            # end TLS session (Amazon SES / Gmail)
            if EcAppParam.gcm_amazonSmtp or EcAppParam.gcm_gmailSmtp:
                l_smtpObj.quit()
        except smtplib.SMTPException as l_exception:
            # if failure, stores the message in a separate file
            EcMailer.cm_mutexFiles.acquire()
            l_fLog = open(re.sub('\.csv', '.rejected_msg', EcAppParam.gcm_logFile), 'a')
            l_fLog.write('>>>>>>>\n' + l_message)
            l_fLog.close()

            # and create a log record in another separate file (distinct from the main log file)
            l_fLog = open(re.sub('\.csv', '.smtp_error', EcAppParam.gcm_logFile), 'a')
            # LOGGER_NAME;TIME;LEVEL;MODULE;FILE;FUNCTION;LINE;MESSAGE
            l_fLog.write(
                'EcMailer;{0};CRITICAL;ec_utilities;ec_utilities.py;sendMail;0;{1}-{2} [step = {3}]\n'.format(
                    datetime.datetime.now(tz=pytz.utc).strftime('%Y-%m-%d %H:%M.%S'),
                    type(l_exception).__name__,
                    re.sub('\s+', ' ', repr(l_exception)),
                    l_stepPassed
                )
            )
            l_fLog.close()
            EcMailer.cm_mutexFiles.release()
        except Exception as e:
            EcMailer.cm_mutexFiles.acquire()
            l_fLog = open(l_fLogName, 'a')
            l_fLog.write(
                '!!!!! {0}-"{1}" [Step = {2}]\n'.format(
                    type(e).__name__,
                    re.sub('\s+', ' ', repr(e)),
                    l_stepPassed
                )
            )
            l_fLog.close()
            EcMailer.cm_mutexFiles.release()


# ----------------- Database connection pool ---------------------------------------------------------------------------
class EcConnectionPool(psycopg2.pool.ThreadedConnectionPool):
    """
    Database connection handling class. Uses Postgres (`psycopg2 <http://initd.org/psycopg/>`_)
    """

    def __init__(self, p_minconn, p_maxconn, *args, **kwargs):
        # logger
        self.m_logger = logging.getLogger('ConnectionPool')

        self.m_logger.info('args : [{0}] kwargs : [{1}]'.format(
            repr(args), repr(kwargs)
        ))

        super().__init__(p_minconn, p_maxconn, *args, **kwargs)

    def getconn(self, p_key=None):
        l_newConn = super().getconn(p_key)

        return l_newConn

    # why do I get a PyCharm warning here ?!
    # It works fine.
    def putconn(self, p_conn, p_key=None, p_close=False):
        super().putconn(p_conn, p_key, p_close)

    def closeall(self):
        super().closeall()