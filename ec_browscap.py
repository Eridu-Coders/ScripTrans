#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

import logging
import csv
import locale
import datetime
import sys
import urllib.request
import urllib.error
import os.path
from io import StringIO

from ec_utilities import EcLogger

class BrowscapCache:
    cm_versionUrl = 'http://browscap.org/version-number'
    cm_fileUrl = 'https://browscap.org/stream?q=BrowsCapCSV'

    def __init__(self, p_pathCsv):
        # logger
        self.m_logger = logging.getLogger('BrowscapCache')

        self.m_logger.info('Loading Browscap local source file:' + p_pathCsv)

        # 0. if no local csv file --> download from BCP server
        if not os.path.isfile(p_pathCsv):
            self.m_logger.info('Local source file not found --> downloading')
            self.downloadCSVFile(BrowscapCache.cm_fileUrl, p_pathCsv)

        # 1. Read the file header in order to determine the local version number ---------------------------------------
        l_localVersion = 0
        try:
            with open(p_pathCsv, 'r') as l_csvFile:
                # figures out the CSV parameters (field sep, string delimiter, ...) hopefully
                l_csvDialect = csv.Sniffer().sniff(l_csvFile.read(4096))

                # Goes back to begining of file
                l_csvFile.seek(0)
                self.m_logger.info('Getting file version and release date')

                # skip top line with "GJK_Browscap_Version","GJK_Browscap_Version"
                l_csvFile.readline()

                l_line = next(csv.reader(StringIO(l_csvFile.readline()), dialect=l_csvDialect))
                # this gets the SECOND line of the file (the first was skipped)
                try:
                    l_localVersion = int(l_line[0])
                except ValueError:
                    self.m_logger.warning('ValueError while converting browscap file version:' + l_line[0])
                    raise
                except Exception as e:
                    self.m_logger.warning('Error while retrieving browscap file version: {0}-{1}'.format(
                        type(e).__name__, repr(e)
                    ))

                self.m_logger.info('Local browcap file version: {0}'.format(l_localVersion))
        except Exception as e:
            self.m_logger.warning('Local browscap file [{0}] exists but cannot be read {1}-{2}'.format(
                p_pathCsv, type(e).__name__, repr(e)
            ))

        # 2. Download latest version number from BCP server ------------------------------------------------------------
        l_latestVersion = self.getLatestVersion(BrowscapCache.cm_versionUrl)

        # 3. if versions differ --> download csv file from BCP server
        if l_latestVersion != l_localVersion:
            self.m_logger.info('Different versions: {0}/{1} --> Downloading [{2}]'.format(
                l_localVersion, l_latestVersion, BrowscapCache.cm_fileUrl))
            self.downloadCSVFile(BrowscapCache.cm_fileUrl, p_pathCsv)

        # 4. load csv file in memory
        l_cacheRows = []
        with open(p_pathCsv, 'r') as l_csvFile:
            # figures out the CSV parameters (field sep, string delimiter, ...) hopefully
            l_csvDialect = csv.Sniffer().sniff(l_csvFile.read(4096))

            # Goes back to begining of file
            l_csvFile.seek(0)

            # skip top line with "GJK_Browscap_Version","GJK_Browscap_Version"
            l_csvFile.readline()

            l_line = next(csv.reader(StringIO(l_csvFile.readline()), dialect=l_csvDialect))
            # this gets the SECOND line of the file (the first was skipped)

            # Determines Browscap file release date --------------------------------------------------------------------
            old_locale = locale.getlocale()
            l_releaseDate = None
            try:
                locale.setlocale(locale.LC_TIME, locale.normalize('en_US.utf8'))
                l_releaseDate = datetime.datetime.strptime(l_line[1][:-6], '%a, %d %b %Y %H:%M:%S')
            except (ValueError, locale.Error):
                self.m_logger.exception(
                    'Error while converting browscap file release date into a datetime:' + l_line[1])
            except Exception as e:
                self.m_logger.warning('Error while retrieving browscap file release date: {0}-{1}'.format(
                    type(e).__name__, repr(e)
                ))
            finally:
                locale.setlocale(locale.LC_TIME, old_locale)

            self.m_logger.info('Local browscap file release date: {0}'.format(l_releaseDate))

            # Start reading data rows ----------------------------------------------------------------------------------
            # the csv lib starts at the THRID line of the file, reads the column headers and then the rows one by one
            self.m_logger.info('Reading browscap user-agent data')
            l_reader = csv.DictReader(l_csvFile, dialect=l_csvDialect)
            l_defaults = {}
            for l_line in l_reader:
                l_line = BrowscapCache.pythonize(l_line)
                if l_line['parent'] == '':
                    # This is the "Default of the Defaults" top line of the file -- Not used
                    continue
                if l_line['parent'] == 'DefaultProperties':
                    # This is the default line for each group of UserAgents --> Stored in defaults
                    l_defaults = l_line
                    continue

                l_cacheRows.append(BrowscapCache.replace_defaults(l_line, l_defaults))

        self.m_logger.info('Size taken by l_cacheRows: {0:,} bytes'.format(sys.getsizeof(l_cacheRows)))

    def downloadCSVFile(self, p_url_file, p_pathCsv, p_timeout=60, p_proxy=None, p_additional_handlers=None):
        """

        :param p_url_file:
        :param p_timeout:
        :param p_proxy:
        :param p_additional_handlers:
        """

        # Download csv file content
        try:
            # url downloader set-up
            l_opener = urllib.request.build_opener()

            if p_proxy is not None:
                self.m_logger.info('Setting up proxy server:' + p_proxy)

                l_opener.add_handler(urllib.request.ProxyHandler({'http': p_proxy}))

                if p_additional_handlers is not None:
                    for handler in p_additional_handlers:
                        p_proxy.add_handler(handler)

            l_opener.addheaders = [('User-agent', 'ec_browscap downloader')]

            urllib.request.install_opener(l_opener)

            # download the file
            l_responseFile = l_opener.open(p_url_file, timeout=p_timeout)
            l_contents_file = l_responseFile.read()
            l_responseFile.close()

            self.m_logger.info('Download of browscap file from url [{0}] complete'.format(p_url_file))
        except urllib.error.URLError as e:
            self.m_logger.warning('Something went wrong while processing urllib handlers ' +
                                  'Url: {0} -- {1}-{2}'.format(p_url_file, type(e).__name__, repr(e)))
            raise
        except Exception as e:
            self.m_logger.warning('Something went wrong while downloading browscap csv file ' +
                                  'Url: {0} -- {1}-{2}'.format(p_url_file, type(e).__name__, repr(e)))
            raise

        # save file content to local CSV file
        try:
            self.m_logger.info('Saving latest version of browscap file to:' + p_pathCsv)
            with open(p_pathCsv, 'wb') as file:
                file.write(l_contents_file)
        except Exception as e:
            self.m_logger.warning('Error while saving latest version of browscap csv file to [{0]]' +
                                  ' -- {1}-{2}'.format(p_pathCsv, type(e).__name__, repr(e)))
            raise

    def getLatestVersion(self, p_url_version, p_timeout=60, p_proxy=None, p_additional_handlers=None):
        """

        :param p_url_version:
        :param p_timeout:
        :param p_proxy:
        :param p_additional_handlers:
        :return: latest version as given by the BCP server
        """
        try:
            # --------------------- Getting latest version number from Browscap site -----------------------------------
            # url downloader set-up
            l_opener = urllib.request.build_opener()

            if p_proxy is not None:
                self.m_logger.info('Setting up proxy server:' + p_proxy)

                l_opener.add_handler(urllib.request.ProxyHandler({'http': p_proxy}))

                if p_additional_handlers is not None:
                    for handler in p_additional_handlers:
                        p_proxy.add_handler(handler)

            l_opener.addheaders = [('User-agent', 'ec_browscap downloader')]

            urllib.request.install_opener(l_opener)

            # download the version number from the version URL
            l_responseVersion = l_opener.open(p_url_version, timeout=p_timeout)
            l_version = bytes.decode(l_responseVersion.read())
            l_responseVersion.close()

            self.m_logger.info('Latest version of browscap file from url [{0}] : {1}'.format(
                p_url_version, l_version))
        except urllib.error.URLError as e:
            self.m_logger.warning('Something went wrong while processing urllib handlers ' +
                                  'Url: {0} -- {1}-{2}'.format(p_url_version, type(e).__name__, repr(e)))
            raise
        except Exception as e:
            self.m_logger.warning('Something went wrong while downloading browscap latest version ' +
                                  'Url: {0} -- {1}-{2}'.format(p_url_version, type(e).__name__, repr(e)))
            raise

        try:
            l_version = int(l_version)
        except ValueError:
            self.m_logger.warning('ValueError while converting browscap file version:' + l_version)
            raise

        return l_version

    @staticmethod
    def replace_defaults(p_line, p_defaults):
        """Replaces 'default' values for a line with parent line value and converting it into native python value.

        :param line: original line from browscap file
        :type line: dict
        :param defaults: default values for current line
        :type defaults: dict
        :returns: dictionary with replaced default values
        :rtype: dict
        :raises: IOError

        """
        l_newLine = {}
        for l_feature, l_value in p_line.items():
            if l_value == 'default' or l_value == '':
                l_value = p_defaults[l_feature]
            if (l_feature == 'Browser_Bits'.lower()
                    or l_feature == 'Platform_Bits'.lower()
                    or l_feature == 'MinorVer') and l_value == 0:
                l_value = p_defaults[l_feature]
            if (l_feature == 'CSSVersion'.lower()
                    or l_feature == 'AolVersion'.lower()
                    or l_feature == 'Version'.lower()
                    or l_feature == 'RenderingEngine_Version'.lower()
                    or l_feature == 'Platform_Version'.lower()) and l_value == 0:
                l_value = p_defaults[l_feature]

            l_newLine[l_feature] = l_value

        return l_newLine
        # end of replace_defaults() ------------------------------------------------------------------------------------

    @staticmethod
    def pythonize(p_line):
        """
        Turn all values in a browscap data row into Python datatypes (bool/int/float).

        :param line: original line from browscap file
        :type line: dict
        :returns: dictionary with values turned into Python data types (bool, int, float)
        :rtype: dict
        """
        l_newLine = {}
        for l_feature, l_value in p_line.items():
            l_featL = l_feature.lower()
            l_valL = l_value.lower()
            if l_valL == 'true':
                l_value = True
            elif l_valL == 'false':
                l_value = False
            elif l_featL == 'MajorVer'.lower() \
                    or l_featL == 'Browser_Bits'.lower() \
                    or l_featL == 'Platform_Bits'.lower() \
                    or l_featL == 'MinorVer'.lower():
                try:
                    l_value = int(l_value)
                except (ValueError, OverflowError):
                    l_value = 0
            elif l_featL == 'CSSVersion'.lower() \
                    or l_featL == 'AolVersion'.lower() \
                    or l_featL == 'Version'.lower() \
                    or l_featL == 'RenderingEngine_Version'.lower() \
                    or l_featL == 'Platform_Version'.lower():
                try:
                    l_value = float(l_value)
                except (ValueError, OverflowError):
                    l_value = float(0)

            l_newLine[l_featL] = l_value
        return l_newLine
        # end of pythonize() ------------------------------------------------------------------------------------


# ---------------------------------------------------- Test section ----------------------------------------------------
if __name__ == "__main__":
    EcLogger.logInit()
    l_browscapCache = BrowscapCache('./browscap.csv')
