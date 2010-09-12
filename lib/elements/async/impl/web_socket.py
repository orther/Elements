# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# The full license is available in the LICENSE file that was distributed with this source code.
#
# Author: Sean Kerr <sean@code-box.org>

import datetime
import hashlib
import mimetypes
import os
import random
import socket
import string
import struct
import time
import urllib
import urlparse

from elements.core           import elements
from elements.core.exception import ClientException
from elements.core.exception import HttpException
from elements.core.exception import ServerException
from elements.async.client   import Client
from elements.async.server   import Server


# ----------------------------------------------------------------------------------------------------------------------
# RESPONSE CODES
# ----------------------------------------------------------------------------------------------------------------------

HTTP_100 = "100 Continue"
HTTP_101 = "101 Switching Protocols"
HTTP_102 = "102 Processing"
HTTP_200 = "200 OK"
HTTP_201 = "201 Created"
HTTP_202 = "202 Accepted"
HTTP_203 = "203 Non-Authoritative Information"
HTTP_204 = "204 No Content"
HTTP_205 = "205 Reset Content"
HTTP_206 = "206 Partial Content"
HTTP_207 = "207 Multi-Status"
HTTP_226 = "226 IM Used"
HTTP_300 = "300 Multiple Choices"
HTTP_301 = "301 Moved Permanently"
HTTP_302 = "302 Found"
HTTP_303 = "303 See Other"
HTTP_304 = "304 Not Modified"
HTTP_305 = "305 Use Proxy"
HTTP_306 = "306 Reserved"
HTTP_307 = "307 Temporary Redirect"
HTTP_400 = "400 Bad Request"
HTTP_401 = "401 Unauthorized"
HTTP_402 = "402 Payment Required"
HTTP_403 = "403 Forbidden"
HTTP_404 = "404 Not Found"
HTTP_405 = "405 Method Not Allowed"
HTTP_406 = "406 Not Acceptable"
HTTP_407 = "407 Proxy Authentication Required"
HTTP_408 = "408 Request Timeout"
HTTP_409 = "409 Conflict"
HTTP_410 = "410 Gone"
HTTP_411 = "411 Length Required"
HTTP_412 = "412 Precondition Failed"
HTTP_413 = "413 Request Entity Too Large"
HTTP_414 = "414 Request-URI Too Long"
HTTP_415 = "415 Unsupported Media Type"
HTTP_416 = "416 Requested Range Not Satisfiable"
HTTP_417 = "417 Expectation Failed"
HTTP_422 = "422 Unprocessable Entity"
HTTP_423 = "423 Locked"
HTTP_424 = "424 Failed Dependency"
HTTP_426 = "426 Upgrade Required"
HTTP_500 = "500 Internal Server Error"
HTTP_501 = "501 Not Implemented"
HTTP_502 = "502 Bad Gateway"
HTTP_503 = "503 Service Unavailable"
HTTP_504 = "504 Gateway Timeout"
HTTP_505 = "505 HTTP Version Not Supported"
HTTP_506 = "506 Variant Also Negotiates"
HTTP_507 = "507 Insufficient Storage"
HTTP_510 = "510 Not Extended"

# ----------------------------------------------------------------------------------------------------------------------

PERSISTENCE_KEEP_ALIVE = 1
PERSISTENCE_PROTOCOL   = 2

# ----------------------------------------------------------------------------------------------------------------------

class WebSocketClient (Client):

    def __init__ (self, client_socket, client_address, server, server_address):
        """
        Create a new WebSocketClient instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server         (Server) The Server instance within which this WebSocketClient is being created.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        Client.__init__(self, client_socket, client_address, server, server_address)

        self._orig_read_delimiter = self.read_delimiter # current read delimiter method

        self.read_delimiter("\r\n", self.handle_request, server._max_request_length)

    # ------------------------------------------------------------------------------------------------------------------

    def compose_headers (self, protocol=None):
        """
        Compose the response headers.

        @param protocol (str)
        """

        out_headers  = "%s\r\n" % " ".join((self.in_headers["SERVER_PROTOCOL"], self.response_code))
        out_headers += "Upgrade: WebSocket\r\n"
        out_headers += "Connection: Upgrade\r\n"

        # Allow specific WebSocket Protocol to be set.
        if protocol:
            out_headers += "Sec-WebSocket-Protocol: %s\r\n" % protocol

        out_headers += "Sec-WebSocket-Origin: %s\r\n" % self.in_headers["HTTP_ORIGIN"]
        out_headers += "Sec-WebSocket-Location: ws://%s%s\r\n\r\n" % (self.in_headers["HTTP_HOST"],
                                                                      self.in_headers["REQUEST_URI"])
        out_headers += self.response_token

        print "RESPONSE HEADER:", out_headers
        self.write(out_headers)

    # ------------------------------------------------------------------------------------------------------------------

    def extract_key_number (self, raw_key):
        """
        Used to parse Sec-WebSocket-Key1 and Sec-WebSocket-Key2 headers.

        @param raw_key (str)

        return (int)
        """

        numbers    = ""
        num_spaces = 0

        for char in raw_key:
            if char in string.digits:
                numbers += char

            elif char == " ":
                num_spaces += 1

        return int(numbers) / num_spaces

    # ------------------------------------------------------------------------------------------------------------------

    def handle_dispatch (self):
        """
        This callback is executed when the request has been parsed and needs dispatched to a handler.
        """

        raise ClientException("WebSocketServer.handle_dispatch() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_message (self):
        """
        This callback is executed when a WebSocket message is received.
        """

        raise ClientException("WebSocketServer.handle_message() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_response_token (self, data):
        """
        This callback is executed when the handshake response token needs to be built.

        @param data (str) The last 8 bytes of the WebSocket request which hold the security 3rd key.
        """

        key1 = self.extract_key_number(self.in_headers['HTTP_SEC_WEBSOCKET_KEY1'])
        key2 = self.extract_key_number(self.in_headers['HTTP_SEC_WEBSOCKET_KEY2'])
        key3 = data

        print "handle_header_input:", (key1, key2, key3)

        key = struct.pack(">II", key1, key2) + key3
        self.response_token = hashlib.md5(key).digest()

        print "handshake_response_token:", (type(self.response_token), self.response_token)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_headers (self, data):
        """
        This callback is executed when the client headers need to be parsed.

        @param data The data that has tentatively been found as the HTTP headers.
        """

        try:
            in_headers = self.in_headers

            # parse headers
            for header in data.rstrip().split("\r\n"):
                header = header.split(": ")

                in_headers["HTTP_" + header[0].upper().replace("-", "_")] = header[1]

            if in_headers["SERVER_PROTOCOL"] == "HTTP/1.1" and in_headers["HTTP_UPGRADE"] == "WebSocket" and\
               in_headers["HTTP_CONNECTION"] == "Upgrade":

                self.read_length(8, self.handle_response_token)

                self.read_delimiter("\xFF", self.handle_message) #, self._server._max_headers_length)

                print "WebSocket Request", data
                self.handle_dispatch()


            else:
                raise HttpException("Bad Request", HTTP_400)

        except HttpException:
            raise

        except Exception as e:
            print e
            raise HttpException("Bad Request1", HTTP_400)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_request (self, data):
        """
        This callback is executed when the initial request line need to be parsed.

        @param data (str) The data that has tentatively been found as the request line.
        """
        self.read_delimiter = self._orig_read_delimiter
        self.response_code  = HTTP_101

        # parse method, uri and protocol
        try:
            data                  = data.rstrip()
            method, uri, protocol = data.split(" ")

        except:
            raise HttpException("Bad Request", HTTP_400)

        # verify method and protocol
        protocol = protocol.upper()

        if protocol not in ("HTTP/1.1"):
            raise HttpException("Bad Request", HTTP_400)

        # initialize headers
        in_headers = { "HTTP_CONTENT_TYPE": "text/plain",
                       "REMOTE_ADDR":       self._client_address[0],
                       "REMOTE_PORT":       self._client_address[1],
                       "REQUEST_METHOD":    method.upper(),
                       "REQUEST_URI":       uri,
                       "SCRIPT_NAME":       uri,
                       "SERVER_ADDR":       self._server_address[0],
                       "SERVER_PORT":       self._server_address[1],
                       "SERVER_PROTOCOL":   protocol }

        # parse querystring
        pos = uri.find("?")

        if pos > -1:
            query_string               = uri[pos + 1:]
            params                     = urlparse.parse_qs(query_string, True)
            in_headers["QUERY_STRING"] = query_string
            in_headers["SCRIPT_NAME"]  = uri[:pos]

            for key, value in params.items():
                if len(value) == 1:
                    params[key] = value[0]

            self.params = params

        else:
            self.params = {}

        self.in_headers = in_headers

        # parse headers
        self.read_delimiter("\r\n\r\n", self.handle_headers, self._server._max_headers_length)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_shutdown (self):
        """
        This callback will be executed when this WebSocketServer instance is shutting down.
        """
        print "Shut down"
        Client.handle_shutdown(self)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_write_finished (self):
        """
        This callback will be executed when the entire write buffer has been written.
        """
        # allowing another request
        self.clear_write_buffer()
        self.read_delimiter("\r\n", self.handle_request, self._server._max_request_length)

# ----------------------------------------------------------------------------------------------------------------------

class WebSocketServer (Server):

    def __init__ (self, gmt_offset="-5", upload_dir="/tmp", upload_buffer_size=50000, max_request_length=5000,
                  max_headers_length=10000, **kwargs):
        """
        Create a new WebSocketServer instance.

        @param gmt_offset         (str) The GMT offset of the server.
        @param upload_dir         (str) The absolute filesystem path to the directory where uploaded files will be
                                        placed.
        @param upload_buffer_size (int) The upload buffer size.
        @param max_request_length (int) The maximum length of the initial request line.
        @param max_headers_length (int) The maximum length for the headers.
        """

        Server.__init__(self, **kwargs)

        self._gmt_offset         = gmt_offset
        self._max_headers_length = max_headers_length
        self._max_request_length = max_request_length
        self._upload_dir         = upload_dir

    # ------------------------------------------------------------------------------------------------------------------

    def handle_client (self, client_socket, client_address, server_address):
        """
        Register a new WebSocketServer instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        raise ServerException("WebSocketServer.handle_client() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_exception (self, exception, client=None):
        """
        This callback is executed when an uncaught exception is found while processing a client.

        @param exception (Exception)       The exception.
        @param client    (WebSocketServer) The WebSocketServer instance that was active during the exception.
        """

        Server.handle_exception(self, exception)

        if not client:
            return

        client.clear_write_buffer()

        if isinstance(exception, HttpException):
            client.write("HTTP %s\r\nServer: %s\r\n\r\n<h1>%s</h1>" % (exception[1], elements.APP_NAME, exception[0]))

        else:
            client.write("HTTP 500 Internal Server Error\r\nServer: %s\r\n\r\n<h1>Internal Server Error</h1>" %
                         elements.APP_NAME)

        client.flush()

