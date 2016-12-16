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
import re
import time
import operator
from io import StringIO

from ec_utilities import EcLogger
from ec_app_param import EcAppParam

class Browscap:
    def __init__(self, p_row):
        self.m_row = p_row

    def __getattr__(self, p_item):
        """
        **CAUTION**: may raise a :any:'KeyError' if the attribute is not in the dict
        """
        return self.m_row[p_item]

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

        self.m_logger.info('Space taken by l_cacheRows: {0:,} bytes'.format(sys.getsizeof(l_cacheRows)))
        self.m_cacheRows = l_cacheRows

        self.initCacheMedium()
        self.initCacheFast()
        self.initCacheHeavy()

    @staticmethod
    def uaPattern2re(p_uaPattern):
        l_re = '^{0}$'.format(re.escape(p_uaPattern))
        l_re = l_re.replace('\\?', '.').replace('\\*', '.*?')

        return l_re

    def idBrowserAnalytic(self, p_ua):
        l_browser = 'Unknown'
        l_platform = 'Unknown'

        l_match  = re.search('((Mozilla|Opera|UCWEB)/\d+\.\d+)(\s|)\(([^\)]*)\)(.*)', p_ua)
        if l_match:
            l_head = l_match.group(1)
            l_body = l_match.group(4)
            l_tail = l_match.group(5)

            #print('{0}/{1}/{2}'.format(l_head, l_body, l_tail))

            l_tailL = l_tail.lower()
            l_bodL = l_body.lower()

            if re.search('opera|opr', l_tailL) or re.search('opera', l_head.lower()):
                l_browser = 'Opera'
            elif re.search('edge', l_tailL):
                l_browser = 'Edge'
            elif re.search('fxios', l_tailL):
                l_browser = 'Firefox'
            elif re.search('ucbrowser', l_tailL):
                l_browser = 'UC Browser'
            elif re.search('msie', l_bodL):
                l_browser = 'IE'
            elif re.search('chromium', l_tailL):
                l_browser = 'Chromium'
            elif re.search('chrome|crios|crmo', l_tailL):
                l_browser = 'Chrome'
            elif re.search('safari', l_tailL):
                l_browser = 'Safari'
            elif re.search('windows.*trident', l_bodL):
                l_browser = 'IE'
            elif re.search('firefox', l_tailL):
                l_browser = 'Firefox'
            elif re.search('gecko', l_tailL):
                l_browser = 'Firefox'

            if re.search('android', l_bodL):
                l_platform = 'Android'
                if l_browser == 'Safari':
                    l_browser = 'Android'
            elif re.search('iphone\sos', l_bodL):
                l_platform = 'iOS'
            elif re.search('ipad', l_bodL):
                l_platform = 'iOS'
            elif re.search('cros', l_bodL):
                l_platform = 'ChromeOS'
            elif re.search('windows\snt\s5', l_bodL):
                l_platform = 'WinXP'
            elif re.search('windows\snt\s6\.0', l_bodL):
                l_platform = 'WinVista'
            elif re.search('windows\snt\s6\.1', l_bodL):
                l_platform = 'Win7'
            elif re.search('windows\snt\s6\.2', l_bodL):
                l_platform = 'Win8'
            elif re.search('windows\snt\s6\.3', l_bodL):
                l_platform = 'Win8.1'
            elif re.search('windows\snt\s10', l_bodL):
                l_platform = 'Win10'
            elif re.search('windows', l_bodL):
                l_platform = 'Windows'
            elif re.search('mac\sos\sx', l_bodL):
                l_platform = 'MacOSX'
            elif re.search('ubuntu', l_bodL):
                l_platform = 'Ubuntu'
            elif re.search('linux', l_bodL):
                l_platform = 'Linux'


        if re.search('safari.*darwin', p_ua.lower()):
            l_browser = 'Safari'
            l_platform = 'iOS'

        if re.search('facebookexternalhit|FBAN|FBAV|FBBV|FBRV|FBDV|FBSN|FBSV|FBSS|FBCR|FBIOS', p_ua):
            l_browser = 'Facebook'

        if re.search('bot|spider|crawl|curl|wget|python|phantomjs', p_ua.lower()):
            l_browser = 'Bot'
            l_platform = ''

        return l_browser, l_platform

    def initCacheHeavy(self):
        self.m_cachePrecompiledHeavy = []

        for l_row in self.m_cacheRows:
            l_re = BrowscapCache.uaPattern2re(l_row['propertyname'])
            self.m_cachePrecompiledHeavy.append((re.compile(l_re), l_row))

    def idBrowserHeavy(self, p_ua):
        if 'm_cachePrecompiledHeavy' not in self.__dict__:
            self.initCacheHeavy()

        for l_reCompiled, l_row in self.m_cachePrecompiledHeavy:
            if l_reCompiled.search(p_ua):
                return Browscap(l_row)

    def idBrowserSlow(self, p_ua):
        for l_row in self.m_cacheRows:
            l_re = BrowscapCache.uaPattern2re(l_row['propertyname'])
            #print(l_re)
            if re.search(l_re, p_ua):
                return Browscap(l_row)

        return None

    def initCacheMedium(self):
        l_deltaVer = 6
        l_browserList = ['Chrome', 'Safari', 'IE', 'Opera', 'Firefox']
        self.m_cachePrecompiled = []
        l_maxVer = dict()
        for l_row in self.m_cacheRows:
            l_browser = l_row['browser']
            l_ver = l_row['majorver']

            if l_browser not in l_browserList:
                continue

            try:
                if l_maxVer[l_browser] < l_ver:
                    l_maxVer[l_browser] = l_ver
            except KeyError:
                l_maxVer[l_browser] = l_ver

        if EcAppParam.gcm_debugModeOn:
            for l_browser in l_maxVer.keys():
                print('Max Ver {0:<20} --> {1}'.format(l_browser, l_maxVer[l_browser]))

        l_countPattern = dict()
        l_totalCount = 0
        for l_row in self.m_cacheRows:
            l_browser = l_row['browser']
            l_ver = l_row['majorver']

            if l_browser not in l_browserList:
                continue

            if l_maxVer[l_browser] - l_ver < l_deltaVer:
                l_re = BrowscapCache.uaPattern2re(l_row['propertyname'])
                self.m_cachePrecompiled.append( (re.compile(l_re), l_row) )
                l_totalCount += 1
                try:
                    l_countPattern[l_browser] += 1
                except KeyError:
                    l_countPattern[l_browser] = 1

        if EcAppParam.gcm_debugModeOn:
            for l_browser in l_countPattern.keys():
                print('Count   {0:<20} --> {1:,}'.format(l_browser, l_countPattern[l_browser]))

            print('Total : {0:,}'.format(l_totalCount))

        self.m_logger.info('Space taken by m_cachePrecompiled: {0:,} bytes'.format(
            sys.getsizeof(self.m_cachePrecompiled)))

    def idBrowserMedium(self, p_ua):
        if 'm_cachePrecompiled' not in self.__dict__:
            self.initCacheMedium()

        for l_reCompiled, l_row in self.m_cachePrecompiled:
            if l_reCompiled.search(p_ua):
                return Browscap(l_row)

    def initCacheFast(self):
        self.m_rePrecompiled = []
        l_reList = [
            ('Chrome',
             'Mozilla/5\.0(\s|)\(.*\).*AppleWebKit/.*\(KHTML.*like\sGecko.*\)(\s|)(Chrome|.*CriOS|.*CrMo)/(\d+\.|).*'),
            ('UC Browser',
             '.*(UCBrowser|UCWEB).*'),
            ('Opera',
             '.*Opera.*'),
            ('IE',
             'Mozilla/(\d\.0|\.*).*\(.*MSIE\s\d+\.(\d+|).*'),
            ('Safari',
             '.*Safari.*'),
            ('Safari',
             'Mozilla/5\.0(\s|)\(.*Mac\sOS\sX.*\).*AppleWebKit/.*'),
            ('Firefox',
             'Mozilla/\d\.0\s\(.*\).*Gecko.*(Firefox/\d+\.\d+.*|)'),
        ]
        for l_browser, l_re in l_reList:
            self.m_rePrecompiled.append((l_browser, re.compile(l_re)))

    def idBrowserFastAndDirty(self, p_ua):
        if 'm_rePrecompiled' not in self.__dict__:
            self.initCacheFast()

        for l_browser, l_reCompiled in self.m_rePrecompiled:
            if l_reCompiled.search(p_ua):
                return l_browser

        return 'Unknows'

    def testMainBrowsers(self):
        l_chromeStandard = 0
        l_chromeElse = 0
        l_firefoxStandard = 0
        l_firefoxElse = 0
        l_ieStandard = 0
        l_ieElse = 0
        l_operaStandard = 0
        l_operaElse = 0
        l_ucStandard = 0
        l_ucElse = 0
        l_safariStandard = 0
        l_safariElse = 0
        for l_row in self.m_cacheRows:
            l_ua = l_row['propertyname']
            l_browser = l_row['browser'].lower()
            # Mozilla/5.0 (*Windows NT 6.3*Win64? x64**********************) AppleWebKit/* (KHTML* like Gecko) Chrome/50.*Safari/*
            # Mozilla/5.0 (*Linux*Android?4.2*Nexus 5 Build/***************) AppleWebKit/* (KHTML* like Gecko*) Chrome/55.*Safari/*
            # Mozilla/5.0 (*Linux*Android?4.1*Ergo Tab Crystal Lite Build/*) AppleWebKit/*(KHTML,*like Gecko) Chrome/55.*Safari/*
            # Mozilla/5.0 (*Linux x86**************************************) AppleWebKit/* (KHTML,*like Gecko) Chrome/55.*
            # Mozilla/5.0 (*Linux*Android?5.0******************************)*AppleWebKit/* (KHTML* like Gecko) Chrome/54.*Safari/*
            # Mozilla/5.0(*Linux*Android?4.4*Fly IQ4409 Quad Build/*) AppleWebKit/*(KHTML* like Gecko) Chrome/54.*Safari/*
            # Mozilla/5.0 (*Windows NT 10.0*WOW64*) AppleWebKit/* (KHTML* like Gecko) Chrome/*Anonymisiert durch*
            # Mozilla/5.0 (iPad*CPU iPhone OS 3?0* like Mac OS X*) AppleWebKit/* (KHTML* like Gecko) *CriOS/55.*Safari/*
            # Mozilla/5.0 (*Linux*Android?4.0*HTC_Sensation Build/*) AppleWebKit/* (KHTML* like Gecko)*CrMo/51.*Safari/*
            if l_browser.lower() == 'chrome':
                if re.search(
                        'Mozilla/5\.0(\s|)\(.*\).*AppleWebKit/.*\(KHTML.*like\sGecko.*\)(\s|)(Chrome|.*CriOS|.*CrMo)/(\d+\.|).*', l_ua):
                    #print('Match:' + l_ua)
                    l_chromeStandard += 1
                else:
                    #print('Chrome No Match:' + l_ua)
                    l_chromeElse += 1

            # Mozilla/5.0 (*Windows NT 5.0; *WOW64*) Gecko* Firefox/46.0*
            # Mozilla/4.0 (*Windows NT 10.0*WOW64*) Gecko* Firefox/50.0*
            # Mozilla/5.0 (*Windows NT 6.4*rv:50.0*) Gecko*/
            # Mozilla/5.0 (Tablet; rv:37.0*)*Gecko*Firefox/37.0*
            if l_browser.lower() == 'firefox':
                if re.search('Mozilla/\d\.0\s\(.*\).*Gecko.*(Firefox/\d+\.\d+.*|)', l_ua):
                    # print('Match:' + l_ua)
                    l_firefoxStandard += 1
                else:
                    # print('Firefox No Match:' + l_ua)
                    l_firefoxElse += 1

            # Mozilla/5.0 (compatible; MSIE 7.0; *Windows NT 6.1*Win64? x64*Trident/4.0*Mozilla/4.0 (compatible; MSIE 6.0*
            # Mozilla/5.0 (compatible; MSIE 7.*Windows NT 6.0*Trident/6.0*)*
            if l_browser.lower() == 'ie':
                if re.search('Mozilla/(\d\.0|\.*).*\(.*MSIE\s\d+\.(\d+|).*', l_ua):
                    # print('Match:' + l_ua)
                    l_ieStandard += 1
                else:
                    # print('IE No Match:' + l_ua)
                    l_ieElse += 1

            # Mozilla/5.0 (*Windows NT 6.2*Win64? x64*) AppleWebKit/* (KHTML, like Gecko)*Chrome/*Safari/*OPR/35.0*
            # Mozilla/5.0 (*Windows NT 6.2*Win64? x64*) AppleWebKit/* (KHTML, like Gecko)*Chrome/*Safari/*OPR/*
            # Opera/9.80*(*Windows NT 5.2*)*Version/*
            # Mozilla/?.*(*Mac OS X 10?10*)*Opera?3.00*
            # Mozilla/5.0 (compatible; MSIE *Windows NT 6.2*Win64? x64*)*Opera*
            if l_browser.lower() == 'opera':
                if re.search('.*Opera.*', l_ua):
                    # print('Match:' + l_ua)
                    l_operaStandard += 1
                else:
                    # print('Opera No Match:' + l_ua)
                    l_operaElse += 1

            # Mozilla/5.0 (*Linux*Android?5.0* Build/*) AppleWebKit/* (KHTML, like Gecko) Version/* UCBrowser/10.7* U3/* Safari/*
            # Mozilla/5.0 (*Linux*Android?2.3*) AppleWebKit/* (KHTML,*like Gecko*) UCBrowser/2.3*Safari/*
            # Mozilla/5.0 (*CPU iPhone OS 9?0* like Mac OS X*)*AppleWebKit/*(*KHTML* like Gecko*)*UCBrowser/*
            if l_browser.lower() == 'uc browser':
                if re.search('.*(UCBrowser|UCWEB).*', l_ua):
                    # print('Match:' + l_ua)
                    l_ucStandard += 1
                else:
                    # print('UC No Match:' + l_ua)
                    l_ucElse += 1

            # Mozilla/5.0*(iPhone*CPU iPhone OS 5?1* like Mac OS X*)*AppleWebKit/*(*KHTML, like Gecko*)*Version/8.1*Safari/*
            # Mozilla/5.0 (*Mac OS X 10?4*) AppleWebKit/* (KHTML* like Gecko) *Version/3.2* Safari/*
            # Mozilla/5.0 (*Windows NT 6.2*) AppleWebKit/* (KHTML* like Gecko) *Version/5.0* Safari/*
            # Mozilla/5.0 (*Linux*x86_64*) AppleWebKit/* (KHTML* like Gecko) *Version/7.1* Safari/*
            if l_browser.lower() == 'safari':
                if re.search('Mozilla/\d\.\d.*\(.*\).*AppleWebKit/.*\(.*KHTML.*like\sGecko.*\).*Version/\d+\.\d+.*Safari/.*', l_ua):
                    # print('Match:' + l_ua)
                    l_safariStandard += 1
                else:
                    print('Safari No Match:' + l_ua)
                    l_safariElse += 1

        print('l_chromeStandard  : {0}'.format(l_chromeStandard))
        print('l_chromeElse      : {0}'.format(l_chromeElse))

        print('l_firefoxStandard : {0}'.format(l_firefoxStandard))
        print('l_firefoxElse     : {0}'.format(l_firefoxElse))

        print('l_ieStandard      : {0}'.format(l_ieStandard))
        print('l_ieElse          : {0}'.format(l_ieElse))

        print('l_operaStandard   : {0}'.format(l_operaStandard))
        print('l_operaElse       : {0}'.format(l_operaElse))

        print('l_ucStandard      : {0}'.format(l_ucStandard))
        print('l_ucElse          : {0}'.format(l_ucElse))

        print('l_safariStandard  : {0}'.format(l_safariStandard))
        print('l_safariElse      : {0}'.format(l_safariElse))

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
def reTest():
    # Mozilla / 5.0(*MSIE 10.0 * Windows * Trident / 6.0 *) *
    # Mozilla\s/\s5\.0\(.*MSIE\s\d+\.\d+.*\).*
    for l_ua in ['Mozilla/5.0 (*Windows NT 6.3*Win64? x64*) AppleWebKit/* (KHTML, like Gecko) Chrome/50.*Safari/*',
        'Mozilla/5.0 (*Linux*Android?4.1*GT-N8000 Build/*) AppleWebKit/* (KHTML* like Gecko) Chrome/55.*Safari/*',
        'Mozilla/5.0 (*Linux*Android?4.0*Archos 80 Xenon Build/*) AppleWebKit/* (KHTML* like Gecko) Chrome/55.*Safari/*',
        'Mozilla/5.0 (*Windows NT 5.2*) AppleWebKit/* (KHTML* like Gecko) Chrome/55.*Chrome anonymized by*',
        'Mozilla/5.0 (*Windows NT 6.1*WOW64*) AppleWebKit/* (KHTML* like Gecko) Chrome/55.*']:
        if re.search('Mozilla/5\.0\s\(.*\)\sAppleWebKit/.*\s\(KHTML.*\slike\sGecko\)\sChrome/\d+\..*', l_ua):
            print('match    :' + l_ua)
        else:
            print('no match :' + l_ua)


    for l_ua in ['Mozilla / 5.0(*MSIE 10.0 * Windows * Trident / 6.0 *) *']:
        if re.search('Mozilla\s/\s5\.0\(.*MSIE\s\d+\.\d+.*\).*', l_ua):
            print('match    :' + l_ua)
        else:
            print('no match :' + l_ua)

def printSortedDict(p_dict):
    for l_key, l_val in sorted(p_dict.items(), key=operator.itemgetter(1)):
        print('{0:<30} : {1}'.format(l_key, l_val))

if __name__ == "__main__":
    l_uaList = []
    with open('TB_UA.txt', 'r') as l_uaFile:
        for l_rowUA in l_uaFile:
            l_match = re.search('(.*);(.*)', l_rowUA)
            if l_match:
                l_ua = l_match.group(1)
                l_uaList.append(l_ua)

    EcLogger.logInit()
    #reTest()
    t0 = time.perf_counter()
    l_browscapCache = BrowscapCache('./browscap.csv')
    t1 = time.perf_counter()
    l_totalTime = t1-t0
    print('Load : {0:.2f} s.'.format(l_totalTime))

    #l_browscapCache.testMainBrowsers()
    # [
    #   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/601.7.8',
    #   'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36',
    #   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:48.0) Gecko/20100101 Firefox/48.0']

    l_misBrowser = dict()
    l_misBot = dict()
    l_misPlatform = dict()
    l_uaCounter = 0
    for l_ua in l_uaList:
        print('[{0}] {1}'.format(l_uaCounter, l_ua))
        l_uaCounter += 1

        #t0 = time.perf_counter()
        #l_bro = l_browscapCache.idBrowserFastAndDirty(l_ua)
        #t1 = time.perf_counter()
        #l_totalTime = t1-t0
        #print('Fast  : {0:f} s. / {1}'.format(l_totalTime, l_bro))

        t0 = time.perf_counter()
        l_brA, l_ptfA = l_browscapCache.idBrowserAnalytic(l_ua)
        t1 = time.perf_counter()
        l_totalTime = t1-t0
        print('Anal. : {0:f} s. --> {1}/{2}'.format(l_totalTime, l_brA, l_ptfA))

        t0 = time.perf_counter()
        l_br = l_browscapCache.idBrowserHeavy(l_ua)
        l_brB = l_br.browser if l_br is not None else 'Unknown'
        l_ptfB = l_br.platform if l_br is not None else 'Unknown'
        t1 = time.perf_counter()
        l_totalTime = t1-t0
        print('Heavy : {0:f} s. --> {1}/{2}'.format(l_totalTime, l_brB, l_ptfB))

        if l_brA != l_brB:
            l_key = l_brA + '/' + l_brB

            if l_brA == 'Bot':
                try:
                    l_misBot[l_key] += 1
                except KeyError:
                    l_misBot[l_key] = 1
            else:
                try:
                    l_misBrowser[l_key] += 1
                except KeyError:
                    l_misBrowser[l_key] = 1

        if l_ptfA != l_ptfB:
            l_key = l_ptfA + '/' + l_ptfB
            try:
                l_misPlatform[l_key] += 1
            except KeyError:
                l_misPlatform[l_key] = 1

    print('----- Browsers ---------------------')
    printSortedDict(l_misBrowser)
    print('----- Bots -------------------------')
    printSortedDict(l_misBot)
    print('----- Platforms --------------------')
    printSortedDict(l_misPlatform)

