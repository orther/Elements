# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# The full license is available in the LICENSE file that was distributed with this source code.
#
# Author: Brandon Orther <brandon.orther@think-done.com>

import hashlib
import string
import struct
import urlparse

from elements.core            import elements
from elements.core.exception  import ClientException
from elements.core.exception  import HttpException
from elements.core.exception  import ServerException
from elements.async.impl.http import HttpClient
from elements.async.impl.http import HttpServer
from elements.async.server    import Server

# ----------------------------------------------------------------------------------------------------------------------
# RESPONSE CODES
# ----------------------------------------------------------------------------------------------------------------------

HTTP_101 = "101 Switching Protocols"
HTTP_400 = "400 Bad Request"
HTTP_500 = "500 Internal Server Error"

# ----------------------------------------------------------------------------------------------------------------------

class WebSocketClient (HttpClient):

    def _handle_message (self, framed_message):
        """
        This removes the frame from the WebSocket message and then passes it to self.handle_message and then starts
        listening for the next WebSocket message.
        """

        self.handle_message(framed_message[1:-1])

        self._listen_for_message()

    # ------------------------------------------------------------------------------------------------------------------

    def _listen_for_message (self):
        """
        Listen for incoming WebSocket messages.
        """

        self.read_delimiter("\xFF", self._handle_message, self._server._max_request_length)

    # ------------------------------------------------------------------------------------------------------------------

    def compose_headers (self, protocol=None):
        """
        Compose the response headers.

        @param protocol (str)
        """

        if self._is_web_socket_connection:
            out_headers  = "%s %s\r\n" % (self.in_headers["SERVER_PROTOCOL"], HTTP_101)
            out_headers += "Upgrade: WebSocket\r\n"
            out_headers += "Connection: Upgrade\r\n"

            # allow specific WebSocket Protocol to be set.
            if protocol:
                out_headers += "Sec-WebSocket-Protocol: %s\r\n" % protocol

            out_headers += "Sec-WebSocket-Origin: %s\r\n" % self.in_headers["HTTP_ORIGIN"]
            out_headers += "Sec-WebSocket-Location: ws://%s%s\r\n\r\n" % (self.in_headers["HTTP_HOST"],
                                                                          self.in_headers["REQUEST_URI"])
            out_headers += self.response_token

            self.write(out_headers)

        else:
            # compose non-websocket headers
            HttpClient.compose_headers(self)

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

    def handle_web_socket_connect (self):
        """
        This callback is executed when the request has been parsed and a response header is needed to complete the
        WebSocket connection.
        """

        raise ClientException("WebSocketServer.handle_web_socket_connect() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_content_negotiation (self):
        """
        This callback will be executed after the headers have been parsed and content negotiation needs to start.
        """

        if self.in_headers["SERVER_PROTOCOL"] == "HTTP/1.1" and self.in_headers["HTTP_UPGRADE"] == "WebSocket" and\
           self.in_headers["HTTP_CONNECTION"] == "Upgrade":

            self._is_web_socket_connection = True

            if "HTTP_SEC_WEBSOCKET_PROTOCOL" in self.in_headers:
                self.in_web_socket_protocol = self.in_headers["HTTP_SEC_WEBSOCKET_PROTOCOL"]

            # read in 3rd security key and build response token
            self.read_length(8, self.handle_response_token)

            self.handle_web_socket_connect()

            self._listen_for_message()

        else:
            # non-websocket http request
            self._is_web_socket_connection = False

            HttpClient.handle_content_negotiation(self)

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

        key = struct.pack(">II", key1, key2) + key3
        self.response_token = hashlib.md5(key).digest()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_shutdown (self):
        """
        This callback will be executed when this WebSocketServer instance is shutting down.
        """

        if self._is_web_socket_connection:
            print "Web Socket Shut down"

        else:
            HttpClient.handle_shutdown(self)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_write_finished (self):
        """
        This callback will be executed when the entire write buffer has been written.
        """

        if self._is_web_socket_connection:
            # allowing another request
            self.clear_write_buffer()

        else:
            HttpClient.handle_write_finished(self)

    # ------------------------------------------------------------------------------------------------------------------

    def write_message (self, message):
        """
        Write a WebSocket message wrapped in a frame.

        @param message (str)
        """

        self.write("\x00%s\xFF" % message)

# ----------------------------------------------------------------------------------------------------------------------

class WebSocketServer (HttpServer):

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
        print "THIS IS A TEST!!!", exception

        HttpServer.handle_exception(self, exception)
