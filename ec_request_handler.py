#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = 'fi11222'

import http.server

# ----------------------------------------- New Request Handler --------------------------------------------------------
class EcRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    HTTP request handler. Subclass of :any:`http.server.SimpleHTTPRequestHandler` from python std. lib.
    """