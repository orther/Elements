# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# The full license is available in the LICENSE file that was distributed with this source code.
#
# Author: Sean Kerr <sean@code-box.org>

try:
    import cStringIO as StringIO
except:
    import StringIO

import datetime
import mimetypes
import os
import random
import re
import socket
import string
import time
import urllib
import urlparse

import settings

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
# ERROR CODES
# ----------------------------------------------------------------------------------------------------------------------

ERROR_UPLOAD_MAX_SIZE = 1

# ----------------------------------------------------------------------------------------------------------------------
# MISC SETTINGS
# ----------------------------------------------------------------------------------------------------------------------

FILE_READ_SIZE = 131070

PERSISTENCE_KEEP_ALIVE = 1
PERSISTENCE_PROTOCOL   = 2

# ----------------------------------------------------------------------------------------------------------------------

class HttpAction:

    def __init__ (self, server, title="Method Not Allowed", response_code=HTTP_405):
        """
        Create a new HttpAction instance.

        @param server        (HttpServer) The HttpServer instance.
        @param title         (str)        The title to display when this core action handles a request.
        @param response_code (str)        The response code to use when this core action handles a request.
        """

        self._server         = server
        self.__response_code = response_code
        self.__title         = title

    # ------------------------------------------------------------------------------------------------------------------

    def connect (self, client):
        """
        Handle a CONNECT request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def delete (self, client):
        """
        Handle a DELETE request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def get (self, client):
        """
        Handle a GET request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def head (self, client):
        """
        Handle a HEAD request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def options (self, client):
        """
        Handle a OPTIONS request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def post (self, client):
        """
        Handle a POST request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def put (self, client):
        """
        Handle a PUT request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def trace (self, client):
        """
        Handle a TRACE request.

        @param client (HttpClient) The HttpClient instance.
        """

        client.response_code = self.__response_code

        client.compose_headers()
        client.write("<h1>%s</h1>" % self.__title)
        client.flush()

# ----------------------------------------------------------------------------------------------------------------------

class HttpClient (Client):

    def __init__ (self, client_socket, client_address, server, server_address):
        """
        Create a new HttpClient instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server         (Server) The Server instance within which this HttpClient is being created.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        Client.__init__(self, client_socket, client_address, server, server_address)

        self._chunked_write_buffer    = StringIO.StringIO() # chunk encoding write buffer
        self._is_allowing_persistence = False               # indicates that this client allows persistence
        self._is_headers_written      = False               # indicates that the headers have been written
        self._max_persistent_requests = None                # maximum persistent requests allowed
        self._multipart_file          = None                # current multipart upload file
        self._orig_flush              = self.flush          # original flush method
        self._orig_read_delimiter     = self.read_delimiter # original read delimiter method
        self._orig_write              = self.write          # original write method
        self._request_count           = 0                   # count of served requests (only useful if persistence is
                                                            # enabled)

        # files variable must exist because it's access in handle_shutdown(), and handle_shutdown() is always called,
        # even in the event that a timeout occurred before a request could physically be handled
        self.__files = []

        # read until we get the initial request line
        self.read_delimiter("\r\n", self.handle_request, settings.http_max_request_length)

    # ------------------------------------------------------------------------------------------------------------------

    def allow_persistence (self, status, max_requests=None):
        """
        Set the persistence status.

        @param status       (bool) The persistence status.
        @param max_requests (int)  The maximum persistent requests to serve before the connection will be closed.
        """

        self._is_allowing_persistence = status
        self._max_persistent_requests = max_requests

    # ------------------------------------------------------------------------------------------------------------------

    def compose_headers (self, chunked_encoding=True):
        """
        Compose the response headers.

        @param chunked_encoding (bool) Indicates that chunked encoding should be used.
        """

        if self._is_headers_written:
            return

        chunked_encoding = chunked_encoding and self.in_headers["SERVER_PROTOCOL"] != "HTTP/1.0" and \
                           not self._static_file
        out_headers      = self.out_headers

        # required headers
        out_headers["Content-Type"] = self.content_type
        out_headers["Server"]       = elements.APP_NAME

        if chunked_encoding:
            out_headers["Transfer-Encoding"] = "chunked"

        # handle persistence
        if self._max_persistent_requests and self._request_count >= self._max_persistent_requests:
            self._persistence_type = None

        elif self._is_allowing_persistence:
            if self._persistence_type:
                out_headers["Connection"] = "keep-alive"

            else:
                out_headers["Connection"] = "close"

        # build the request head
        self.write(" ".join((self.in_headers["SERVER_PROTOCOL"], self.response_code)))
        self.write("\r\n")
        self.write("\r\n".join(["%s: %s" % header for header in out_headers.items()]))
        self.write("\r\n")

        if self.out_cookies:
            self.write("\r\n".join(["Set-Cookie: %s" % cookie for cookie in self.out_cookies.values()]))
            self.write("\r\n")

        self.write("\r\n")
        self.flush()

        if chunked_encoding:
            # future flush and write operations must use a chunked encoding
            self.flush = self.__chunked_flush
            self.write = self.__chunked_write

        self._is_headers_written = True

    # ------------------------------------------------------------------------------------------------------------------

    def handle_content_negotiation (self):
        """
        This callback will be executed after the headers have been parsed and content negotiation needs to start.
        """

        # check content type
        content_type = self.in_headers.get("HTTP_CONTENT_TYPE", "text/plain").lower()

        if content_type == "text/plain":
            # nothing else to do, just dispatch the request
            self.handle_dispatch()

        elif content_type == "application/x-www-form-urlencoded":
            # request contains encoded content
            try:
                content_length = int(self.in_headers["HTTP_CONTENT_LENGTH"])

            except:
                # length required
                self._server._error_actions[HTTP_411][1].get(self)

                return

            # read until we get all of the encoded data
            self.read_length(content_length, self.handle_urlencoded_content)

        elif content_type.startswith("multipart/form-data"):
            # request contains multipart content
            self._multipart_boundary = "--" + content_type[30:]

            # read until we have consumed all of the boundary details
            self.read_length(len(self._multipart_boundary), self.handle_multipart_boundary)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_dispatch (self):
        """
        This callback will be executed when the request has been parsed and needs dispatched to a handler.
        """

        raise ClientException("HttpClient.handle_dispatch() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_headers (self, data):
        """
        This callback will be executed when headers are ready to be parsed.

        @param data (str) The data that has tentatively been found as the HTTP headers.
        """

        try:
            in_cookies = self.in_cookies
            in_headers = self.in_headers

            # parse headers
            for header in data.rstrip().split("\r\n"):
                header = header.split(": ")

                in_headers["HTTP_" + header[0].upper().replace("-", "_")] = header[1]

            # parse cookies
            if "HTTP_COOKIE" in in_headers:
                for cookie in in_headers["HTTP_COOKIE"].split(";"):
                    cookie = cookie.rstrip().split("=", 1)

                    in_cookies[cookie[0]] = cookie[1]

            # check persistence
            if in_headers["SERVER_PROTOCOL"] == "HTTP/1.1":
                self._persistence_type = PERSISTENCE_PROTOCOL

            elif in_headers.get("HTTP_CONNECTION", "").lower() == "keep-alive":
                self._persistence_type = PERSISTENCE_KEEP_ALIVE

        except:
            # bad request
            self._server._error_actions[HTTP_400][1].get(self)

        # start content negotiation
        self.handle_content_negotiation()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_max_bytes (self, max_bytes):
        """
        This callback will be executed when a maximum byte limit has been met.

        @param max_bytes (int) The maximum byte limit.

        @return (bool) True, if processing should continue, otherwise False.
        """

        # bad request
        self._server._error_actions[HTTP_400][1].get(self)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_multipart_boundary (self, data):
        """
        This callback will be executed when a multipart boundary has been located.

        @param data (str) The multipart boundary.
        """

        # read until we have consumed the 2 bytes (CRLF) after the boundary
        self.read_length(2, self.handle_multipart_post_boundary)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_multipart_headers (self, data):
        """
        This callback will be executed when multipart headers need to be parsed.

        @param data (str) The data that has tentatively been found as multipart headers.
        """

        try:
            # parse headers
            headers = {}

            for header in data.rstrip().split("\r\n"):
                header = header.split(": ")

                headers[header[0].upper()] = header[1]

            disposition = headers["CONTENT-DISPOSITION"][11:]
            name        = disposition[6:disposition.find("\"", 6)].decode("utf-8")
            pos         = disposition.find("filename=\"")

            self.read_delimiter  = self.multipart_read_delimiter
            self._multipart_name = name

            if pos == -1:
                # read until we have all of the field data
                self.read_delimiter(self._multipart_boundary, self.handle_multipart_post_boundary, 1000)

                return

            # file upload
            pos += 10

            if not self.files:
                self.files = {}

            # enlarge the read size so uploads are quicker
            content_length = int(self.in_headers.get("HTTP_CONTENT_LENGTH", 0))

            if content_length >= 1048576:
                # content is at least a meg, use a rather large read size
                self._orig_read_size = self._read_size
                self._read_size      = 131070

            else:
                # content is potentially large, use a moderate read size
                self._orig_read_size = self._read_size
                self._read_size      = 65535

            # open a temp file to store the upload
            chars     = "".join((string.letters, string.digits))
            temp_name = "/".join((settings.http_upload_dir, "".join([random.choice(chars) for x in xrange(0, 25)])))

            file = { "error":      None,
                     "filename":   disposition[pos:disposition.find("\"", pos)],
                     "size":       0,
                     "temp_name":  temp_name }

            # add temp filename to list
            self.__files.append(temp_name)

            # determine mimetype
            mimetype = mimetypes.guess_type(file["filename"])

            if mimetype[0]:
                file["content_type"] = mimetype[0]

            elif mimetype[1]:
                file["content_type"] = "+".join(("text/", mimetype[1]))

            else:
                file["content_type"] = "text/plain"

            if name in self.files:
                if type(self.files[name]) != list:
                    # convert individual file to list
                    self.files[name] = [self.files[name]]

                self.files[name].append(file)

            else:
                self.files[name] = file

            self._is_multipart_maxed  = False
            self._multipart_file      = open(temp_name, "wb+")
            self._multipart_file_size = 0

        except:
            # bad request
            self._server._error_actions[HTTP_400][1].get(self)

        # read until we hit the boundary
        self.read_delimiter(self._multipart_boundary, self.handle_multipart_post_boundary)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_multipart_post_boundary (self, data):
        """
        This callback will be executed when a multipart post boundary has been located.

        @param data (str) The multipart post boundary.
        """

        if data == "\r\n":
            # read until we hit the end of the multipart headers
            self.read_delimiter("\r\n\r\n", self.handle_multipart_headers)

            return

        elif data == "--":
            # no more multipart data
            self.handle_dispatch()

            return

        # bad request
        self._server._error_actions[HTTP_400][1].get(self)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_request (self, data):
        """
        This callback will be executed when the initial request line needs parsed.

        @param data (str) The data that has tentatively been found as the request line.
        """

        self.__files              = []
        self._is_headers_flushed  = False
        self._multipart_file      = None
        self._persistence_type    = None
        self._request_count      += 1
        self._static_file         = None
        self.content_type         = "text/html"
        self.files                = None
        self.flush                = self._orig_flush
        self.in_cookies           = {}
        self.out_cookies          = {}
        self.out_headers          = {}
        self.read_delimiter       = self._orig_read_delimiter
        self.response_code        = HTTP_200
        self.write                = self._orig_write

        # parse method, uri and protocol
        try:
            data                  = data.rstrip()
            method, uri, protocol = data.split(" ")

        except:
            try:
                method, uri = data.split(" ")
                protocol    = "HTTP/1.0"

            except:
                # bad request
                self._server._error_actions[HTTP_400][1].get(self)

                return

        # verify method and protocol
        method   = method.upper()
        protocol = protocol.upper()

        if method not in ("CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE"):
            # method not allowed
            self._server._error_actions[HTTP_405][1].get(self)

            return

        if protocol not in ("HTTP/1.0", "HTTP/1.1"):
            # http protocol not supported
            self._server._error_actions[HTTP_505][1].get(self)

            return

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

        # read until we hit the end of the headers
        self.read_delimiter("\r\n\r\n", self.handle_headers, settings.http_max_headers_length)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_shutdown (self):
        """
        This callback will be executed when this HttpClient instance is shutting down.
        """

        # close the current multipart upload file pointer if one exists
        if self._multipart_file and not self._is_multipart_maxed:
            try:
                self._multipart_file.close()

            except:
                pass

        # delete all temp files
        for file in self.__files:
            try:
                os.unlink(file)

            except:
                pass

        Client.handle_shutdown(self)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_upload_finished (self, file):
        """
        This callback will be executed when an upload file has finished.

        @param file (dict) The dict of upload details.

        @return (bool) True, if the upload is ok, otherwise False.
        """

        return True

    # ------------------------------------------------------------------------------------------------------------------

    def handle_urlencoded_content (self, data):
        """
        This callback will be executed when urlencoded content is ready to be parsed.

        @param data (str) The content.
        """

        params = self.params

        for key, value in urlparse.parse_qs(data.rstrip()).items():
            if key in params:
                values = params[key]

                if type(values) == list:
                    values.extend(value)

                    continue

                values      = [values]
                params[key] = values

                values.extend(value)

            else:
                if len(value) == 1:
                    # individual param value, so let's extract it out of the list
                    params[key] = value[0]

                    continue

                params[key] = value

        # dispatch the client
        self.handle_dispatch()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_write_finished (self):
        """
        This callback will be executed when the entire write buffer has been written.
        """

        if self._static_file:
            # serving a static file
            data = self._static_file.read(FILE_READ_SIZE)

            if len(data) > 0:
                # more data to write
                self.write(data)
                self.flush()

                return

            # finished reading file
            self._static_file.close()

            self._static_file = None

            self.clear_events()

        else:
            if self._is_allowing_persistence and self._persistence_type:
                # allowing another request
                self.clear_write_buffer()

                # read until we hit the end of the headers
                self.read_delimiter("\r\n", self.handle_request, settings.http_max_request_length)

                return

            # clear the events so the server inits the shutdown sequence
            self.clear_events()

    # ------------------------------------------------------------------------------------------------------------------

    def multipart_read_delimiter (self, delimiter, callback, max_bytes=0):
        """
        Read until a certain delimiter has been found within the multipart read buffer.

        @param delimiter (str)    The delimiter to find.
        @param callback  (method) The callback to execute once the delimiter has been found.
        @param max_bytes (int)    The maximum byte limit to read.
        """

        buffer         = self._read_buffer
        data           = buffer.getvalue()
        multipart_file = self._multipart_file
        multipart_name = self._multipart_name
        params         = self.params
        pos            = data.find(delimiter)

        if not multipart_file:
            # form field
            if pos > -1:
                # boundary has been found
                if multipart_name in params:
                    if type(params[multipart_name]) != list:
                        # param already existed, but wasn't a list so let's convert it
                        params[multipart_name] = [params[multipart_name]]

                    params[multipart_name].append(data[:pos - 2])

                else:
                    params[multipart_name] = data[:pos - 2]

                self.read_delimiter = self._orig_read_delimiter

                buffer.truncate(0)
                buffer.write(data[pos + len(delimiter):])

                # read until we consume 2 bytes (CRLF)
                self.read_length(2, callback)

                return

        else:
            # file upload
            file = self.files[multipart_name]

            if type(file) == list:
                file = file[-1]

            if pos > -1:
                # boundary has been found, write the buffer minus 2 bytes (for \r\n) to the file
                self._multipart_file = None
                self.read_delimiter  = self._orig_read_delimiter

                chunk = data[:pos - 2]

                if not self._is_multipart_maxed:
                    # flush end contents
                    multipart_file.write(chunk)
                    multipart_file.flush()
                    multipart_file.close()

                    self._read_size = self._orig_read_size

                    self._multipart_file_size += len(chunk)

                    if settings.http_max_upload_size and settings.http_max_upload_size < self._multipart_file_size:
                        # upload is too big
                        file["error"] = ERROR_UPLOAD_MAX_SIZE

                buffer.truncate(0)
                buffer.write(data[pos + len(delimiter):])

                file["size"] = os.stat(file["temp_name"]).st_size

                self.handle_upload_finished(file)

                # read until we consume 2 bytes (CRLF)
                self.read_length(2, callback)

                return

            # boundary has not been found
            if len(data) >= settings.http_upload_buffer_size:
                # flush the buffer to file
                chunk = data[:-len(delimiter)]

                self._multipart_file_size += len(chunk)

                if not self._is_multipart_maxed:
                    # write another chunk of the file to disk to avoid memory consumption
                    multipart_file.write(chunk)
                    multipart_file.flush()

                buffer.truncate(0)
                buffer.write(data[len(data) - len(delimiter):])

                # check file size limit
                if settings.http_max_upload_size and settings.http_max_upload_size < self._multipart_file_size and \
                   not self._is_multipart_maxed:
                    # upload is too big
                    multipart_file.close()

                    file["error"]            = ERROR_UPLOAD_MAX_SIZE
                    self._is_multipart_maxed = True

        self._read_callback  = callback
        self._read_delimiter = delimiter
        self._read_max_bytes = max_bytes

    # ------------------------------------------------------------------------------------------------------------------

    def raise_error (self, response_code):
        """
        Display an error page for the response code.

        @param response_code (str) The response code.
        """

        try:
            action = self._server._error_actions[response_code]

        except:
            pos = response_code.find(" ")

            if pos > -1:
                raise ClientException("Missing action for error: %s" % response_code[:pos])

            else:
                raise ClientException("Invalid response code: %s" % response_code)

        # execute the action here so any exceptions can be caught by the server
        action[1].get(self)

    # ------------------------------------------------------------------------------------------------------------------

    def set_cookie (self, name, value="", expires=None, path="/", domain=None, http_only=False, secure=False):
        """
        Set a cookie.

        @param name      (str)      The cookie name.
        @param value     (str)      The cookie value.
        @param expires   (datetime) The date and time at which the cookie will expire.
        @param path      (str)      The root path under which the cookie will be valid.
        @param domain    (str)      The domain under which the cookie will be valid.
        @param http_only (bool)     Indicates that the cookie will not be accessible from client script.
        @param secure    (bool)     Indicates that the cookie will only be transmitted over an HTTPS connection.
        """

        cookie = "".join((name, "=", urllib.quote(str(value)), "; path=", path))

        if domain:
            cookie += "; domain=" + domain

        if expires:
            cookie += "; expires=" + datetime.datetime.fromtimestamp(time.time() + expires) \
                                             .strftime("%A, %d %B %Y %H:%M:%S GMT" + settings.http_gmt_offset)

        if http_only:
            cookie += "; HttpOnly"

        if secure:
            cookie += "; secure"

        self.out_cookies[name] = cookie

    # ------------------------------------------------------------------------------------------------------------------

    def serve_static_file (self, path, filename=None):
        """
        Serve a static file.

        @param path     (str) The absolute filesystem path to the file.
        @param filename (str) A substitute download filename.

        @return (bool) True, if the file will be served, otherwise False.
        """

        try:
            file = open(path, "rb")

            self._static_file = file

            if not filename:
                filename = os.path.basename(path)

            self.out_headers["Content-Disposition"] = "attachment; filename=%s" % filename

            # determine mimetype
            mimetype = mimetypes.guess_type(path)

            if mimetype[0]:
                self.content_type = mimetype[0]

            elif mimetype[1]:
                self.content_type = "+".join(("text/", mimetype[1]))

            else:
                self.content_type = "text/plain"

            # compose headers and write the first portion of the file
            self.compose_headers()
            self.write(file.read(FILE_READ_SIZE))
            self.flush()

            return True

        except:
            # file doesn't exist or permission denied
            return False

    # ------------------------------------------------------------------------------------------------------------------

    def __chunked_flush (self, last=True):
        """
        Notify the event manager that there is write data available.

        @param last (bool) Indicates that this is the last chunk of data being flushed.
        """

        # flush using chunked transfer encoding
        buffer = self._chunked_write_buffer
        data   = buffer.getvalue()

        buffer.truncate(0)

        Client.write(self, "".join((hex(len(data))[2:], "\r\n", data, "\r\n")))

        if last:
            # this is the last chunk so write the ending chunk size followed by an empty set of footers
            Client.write(self, "0\r\n\r\n\r\n")

        Client.flush(self)

    # ------------------------------------------------------------------------------------------------------------------

    def __chunked_write (self, data):
        """
        Append data onto the write buffer.
        """

        self._chunked_write_buffer.write(data)

# ----------------------------------------------------------------------------------------------------------------------

class HttpRequest (Client):

    def __init__ (self, server, host, port=80):
        """
        Create a new HttpRequest instance.

        @param server (Server) The Server instance.
        @param host   (str)    The hostname.
        @param port   (int)    The port.
        """

        self._basic_content_types = ["text/plain", "text/html"]
        self._host                = host
        self._port                = port
        self._server              = server
        self._socket              = None
        self.files                = None

        self.reset()

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self._socket.connect((self._host, self._port))
            self._socket.setblocking(0)

            # initialize parent class
            Client.__init__(self, self._socket, (socket.gethostbyname(host), port), server, ('0.0.0.0', 80))

        except Exception, e:
            raise ClientException("Cannot connect to %s: %s" % (self._host, str(e)))

        # register as a client
        server.register_client(self)

    # ------------------------------------------------------------------------------------------------------------------

    def add_basic_content_type (self, content_type):
        """
        Add a content-type that will be stored-in memory as a normal response and handled with handle_finished().
        Any returned content-types that are not listed as basic are written to file and handled with handle_download().

        @param content_type (str) The content type.
        """

        if content_type not in self._basic_content_types:
            self._basic_content_types.append(content_type)

    # ------------------------------------------------------------------------------------------------------------------

    def add_file (self, path):
        """
        Add a file.

        @param path (str) The absolute filesystem path to the file.
        """

        try:
            file     = open(path, "rb")
            filename = os.path.basename(path)

            # determine mimetype
            mimetype = mimetypes.guess_type(filename)

            if mimetype[0]:
                mimetype = mimetype[0]

            elif mimetype[1]:
                mimetype = "+".join(("text/", mimetype[1]))

            else:
                mimetype = "text/plain"

            self.files.append({ "file": file, "filename": filename, "mimetype": mimetype })

        except Exception, e:
            raise ClientException("Cannot add file '%s': %s" % (path, str(e)))

    # ------------------------------------------------------------------------------------------------------------------

    def handle_content_chunk (self, data):
        """
        This callback will be executed for each chunk in a chunked transfer.

        @param data (str) The chunk of data.
        """

        # write all content except the last 2 bytes (the CRLF at the end of the chunk)
        self.content.write(data[:-2])

        # read until we get the chunk length
        self.read_delimiter("\r\n", self.handle_content_chunk_length)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_content_chunk_length (self, data):
        """
        This callback will be executed prior to each chunk in a chunked transfer. This determines the chunk length.

        @param data (str) The chunk length.
        """

        length = int(data.strip().split(";")[0], 16)

        if length > 0:
            # read until we get the entire chunk (add 2 bytes for CRLF)
            self.read_length(length + 2, self.handle_content_chunk)

            return

        self._is_handling_footers = True

        # read until we reach the end of the footers
        self.read_delimiter("\r\n", self.handle_headers)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_content_negotiation (self):
        """
        This callback will be executed after the headers have been parsed and content negotiation needs to start.
        """

        content_type = self.in_headers.get("CONTENT_TYPE", "text/html").split("; ")

        if len(content_type) > 1:
            self.content_encoding = content_type[1]

        self.content_type = content_type[0]

        if self.in_headers.get("TRANSFER_ENCODING", None) == "chunked":
            # read until we get the chunk length
            self.read_delimiter("\r\n", self.handle_content_chunk_length)

        else:
            try:
                content_length = int(self.in_headers.get("CONTENT_LENGTH", 0))

            except:
                raise ClientException("Invalid response content length")

            if content_length == 0:
                raise ClientException("Response contains no content length")

            # read until we get all of the content
            self.read_length(content_length, self.handle_end_content)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_download (self, name, size):
        """
        This callback will be executed when downloadable content is available.

        @param name (str) The file name.
        @param size (int) The file size.

        @return (tuple) Where the first index is a boolean indicating whether or not to store the downloadable content.
                        If False, no more indices are required. If True, an absolute filesystem path including the
                        filename must be supplied.
        """

        return (False, )

    # ------------------------------------------------------------------------------------------------------------------

    def handle_end_content (self, data):
        """
        This callback will be executed when a non-chunked response has been read in its entirety.

        @param data (str) The data.
        """

        self.content = data

        self.handle_finished()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_finished (self):
        """
        This callback will be executed at the end of a successful request.
        """

        raise ClientException("HttpRequest.handle_finished() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_headers (self, data):
        """
        This callback will be executed when headers are ready to be parsed.

        @param data (str) The response headers.
        """

        data = data.rstrip()

        try:
            if len(data) > 0:
                # parse headers
                for header in data.split("\r\n"):
                    name, value = header.split(": ")

                    name = name.upper().replace("-", "_")

                    if name != "SET_COOKIE":
                        # header assignment
                        self.in_headers[name] = value

                        continue

                    # cookie assignment
                    cookie = { "http_only": False,
                               "secure":    False }

                    for i, item in enumerate(value.split(";")):
                        item = item.split("=", 1)

                        if i == 0:
                            # add cookie
                            cookie["value"] = item[1].strip()

                            self.in_cookies[item[0].strip()] = cookie

                            continue

                        if len(item) == 1:
                            if item == "HttpOnly":
                                cookie["http_only"] = True

                            if item == "secure":
                                cookie["secure"] = True

                            continue

                        key, value = item
                        key        = urllib.unquote(key.strip())
                        value      = urllib.unquote(value.strip())

                        cookie[key] = value

                # check persistence
                if self.in_headers.get("CONNECTION", "").lower() != "closed":
                    self.is_allowing_persistence = True

        except Exception, e:
            # invalid response
            raise ClientException("Invalid response headers: %s" % str(e))

        if self._is_handling_footers:
            # end of response
            self.content = self.content.getvalue()

            self.handle_finished()

            return

        # start content negotiation
        self.handle_content_negotiation()

    # ------------------------------------------------------------------------------------------------------------------

    def handle_response_code (self, data):
        """
        Handle the initial response code.

        @param data (str) The status.
        """

        try:
            protocol, response_code, response_message = data.strip().split(" ", 2)

            protocol, protocol_version = protocol.split("/", 1)

        except Exception, e:
            # malformed response line
            raise ClientException("Malformed response line: %s" % data)

        if protocol.upper() != "HTTP":
            # unsupported response protocol
            raise ClientException("Unsupported response protocol: %s" % protocol)

        self._in_protocol_version = protocol_version
        self.response_code        = response_code

        # read until we reach the end of the headers
        self.read_delimiter("\r\n\r\n", self.handle_headers)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_shutdown (self):
        """
        This callback will be executed when this Client instance is shutting down.
        """

        Client.handle_shutdown(self)

        if self.files:
            # close any open files
            for file in self.files:
                try:
                    file["file"].close()

                except:
                    pass

    # ------------------------------------------------------------------------------------------------------------------

    def handle_write_finished (self):
        """
        This callback will be executed when the entire write buffer has been written.
        """

        pass

    # ------------------------------------------------------------------------------------------------------------------

    def open (self, url, method="GET"):
        """
        Open the request.

        @param url    (str) The remote URL.
        @param method (str) The request method. If files or parameters are present, this will automatically be set to
                            POST.
        """

        self.method        = method
        self.url           = url
        encoded_parameters = ""

        # determine whether or not we're sending encoded parameters or a mixture of parameters and files
        if self.parameters and not self.files:
            parameters = []

            for name, value in self.parameters.items():
                if type(value) not in (list, tuple):
                    value = [value]

                for value in value:
                    parameters.append("%s=%s" % (urllib.quote(str(name)), urllib.quote(str(value))))

            encoded_parameters = "&".join(parameters)
            self.method        = "POST"

            self.set_header("Content-Length", str(len(encoded_parameters)))
            self.set_header("Content-Type",   "application/x-www-form-urlencoded")

        elif self.files:
            self.method = "POST"

            self.set_header("Content-Type", "multipart/form-data")

        if self.method not in ("CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE"):
            # unsupported method
            raise ClientException("Unsupported request method: %s" % self.method)

        if not self.url.startswith("/"):
            # the url must start with a forward slash
            self.url = "/" + self.url

        if self.out_protocol_version not in ("1.0", "1.1", "1.2"):
            # must be a recent protocol so we get chunked responses or content-length's
            raise ClientException("HTTP protocol must be 1.0 or newer")

        # write request line, headers and post body (if it exists)
        self.out_headers["Host"] = self._host

        self.write("%s %s HTTP/%s" % (self.method, self.url, self.out_protocol_version))
        self.write("\r\n")
        self.write("\r\n".join(["%s: %s" % header for header in self.out_headers.items()]))
        self.write("\r\n")

        if self.out_cookies:
            self.write("Cookie: " + "; ".join(["%s=%s" % (urllib.quote(name), urllib.quote(value)) \
                                              for name, value in self.out_cookies.items()]))
            self.write("\r\n")

        self.write("\r\n")
        self.write(encoded_parameters)
        self.flush()

        # read until we reach the end of the initial response line
        self.read_delimiter("\r\n", self.handle_response_code)

        # update our events
        self._server.modify_client(self)

    # ------------------------------------------------------------------------------------------------------------------

    def reset (self):
        """
        Reset the request details.
        """

        if self.files:
            # close any open files
            for file in self.files:
                try:
                    file["file"].close()

                except:
                    pass

        self.content                 = StringIO.StringIO()
        self.content_encoding        = None
        self.content_type            = "text/plain"
        self.files                   = []
        self.in_cookies              = {}
        self.in_headers              = {}
        self.is_allowing_persistence = False
        self.is_download             = False
        self.method                  = None
        self.out_cookies             = {}
        self.out_headers             = {}
        self.parameters              = {}
        self.out_protocol_version    = "1.1"
        self.response_code           = None
        self.url                     = None
        self._is_handling_footers    = False

    # ------------------------------------------------------------------------------------------------------------------

    def set_cookie (self, name, value):
        """
        Add a cookie.

        @param name  (str) The cookie name.
        @param value (str) The cookie value.
        """

        self.out_cookies[name] = value

    # ------------------------------------------------------------------------------------------------------------------

    def set_header (self, name, value):
        """
        Set a header.

        @param name  (str) The header name.
        @param value (str) The header value.
        """

        self.out_headers[name] = value

    # ------------------------------------------------------------------------------------------------------------------

    def set_headers (self, headers):
        """
        Merge multiple headers.

        @param headers (dict) The headers to merge.
        """

        self.out_headers.update(headers)

    # ------------------------------------------------------------------------------------------------------------------

    def set_parameter (self, name, value):
        """
        Set a parameter.

        @param name  (str)    The name.
        @param value (object) The value or list of values.
        """

        self.parameters[name] = value

    # ------------------------------------------------------------------------------------------------------------------

    def set_parameters (self, parameters):
        """
        Merge multiple parameters.

        @param parameters (dict) The parameters to merge.
        """

        self.parameters.update(parameters)

# ----------------------------------------------------------------------------------------------------------------------

class HttpServer (Server):

    def __init__ (self, *args, **kwargs):
        """
        Create a new HttpServer instance.
        """

        Server.__init__(self, *args, **kwargs)

        self._error_actions = {}

        # error actions
        self.register_error_action(HTTP_400, HttpAction)
        self.register_error_action(HTTP_402, HttpAction)
        self.register_error_action(HTTP_403, HttpAction)
        self.register_error_action(HTTP_404, HttpAction)
        self.register_error_action(HTTP_405, HttpAction)
        self.register_error_action(HTTP_406, HttpAction)
        self.register_error_action(HTTP_407, HttpAction)
        self.register_error_action(HTTP_408, HttpAction)
        self.register_error_action(HTTP_409, HttpAction)
        self.register_error_action(HTTP_410, HttpAction)
        self.register_error_action(HTTP_411, HttpAction)
        self.register_error_action(HTTP_412, HttpAction)
        self.register_error_action(HTTP_413, HttpAction)
        self.register_error_action(HTTP_414, HttpAction)
        self.register_error_action(HTTP_415, HttpAction)
        self.register_error_action(HTTP_416, HttpAction)
        self.register_error_action(HTTP_417, HttpAction)
        self.register_error_action(HTTP_422, HttpAction)
        self.register_error_action(HTTP_423, HttpAction)
        self.register_error_action(HTTP_424, HttpAction)
        self.register_error_action(HTTP_426, HttpAction)
        self.register_error_action(HTTP_500, HttpAction)
        self.register_error_action(HTTP_501, HttpAction)
        self.register_error_action(HTTP_502, HttpAction)
        self.register_error_action(HTTP_503, HttpAction)
        self.register_error_action(HTTP_504, HttpAction)
        self.register_error_action(HTTP_505, HttpAction)
        self.register_error_action(HTTP_506, HttpAction)
        self.register_error_action(HTTP_507, HttpAction)
        self.register_error_action(HTTP_510, HttpAction)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_client (self, client_socket, client_address, server_address):
        """
        Register a new HttpClient instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        raise ServerException("HttpServer.handle_client() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_exception (self, exception, client=None):
        """
        This callback will be executed when an uncaught exception is found while processing a client.

        @param exception (Exception)  The exception.
        @param client    (HttpClient) The HttpClient instance that was active during the exception.
        """

        Server.handle_exception(self, exception)

        if not client:
            return

        if not client._is_headers_written:
            client.response_code = HTTP_500

            client.compose_headers()
            client.write("<h1>Internal Server Error</h1>")
            client.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def register_error_action (self, response_code, action, args=dict()):
        """
        Register a custom error action.

        @param response_code (str)   The response code under which we're registering the action.
        @param action        (class) The custom error action.
        @param args          (dict)  The action initialization arguments.
        """

        try:
            code, title = response_code.split(" ", 1)

            # test code
            int(code)

        except:
            raise ServerException("Invalid error action response code: %s" % response_code)

        try:
            self._error_actions[response_code] = (None, action(self, title=title, response_code=code, **args))

        except Exception, e:
            raise ServerException("Error action for response code %s failed to instantiate: %s" % (code, str(e)))

# ----------------------------------------------------------------------------------------------------------------------

class RoutingHttpClient (HttpClient):

    def handle_dispatch (self):
        """
        This callback will be executed when the request has been parsed and needs dispatched to a handler.
        """

        route           = self.in_headers["SCRIPT_NAME"].split(":", 1)
        pattern, action = self._server._routes.get(route[0], self._server._error_actions[HTTP_404])

        if not pattern:
            # route doesn't require validated data
            getattr(action, self.in_headers["REQUEST_METHOD"].lower())(self)

            return

        # check for expected data
        if len(route) == 1:
            # route didn't contain data, so it's automatically invalidated (serve 404 as if the url doesn't exist)
            pattern, action = self._server._error_actions[HTTP_404]

            getattr(action, self.in_headers["REQUEST_METHOD"].lower())(self)

            return

        # update headers to reflect proper route details
        self.in_headers["SCRIPT_NAME"], self.in_headers["SCRIPT_ARGS"] = route

        # validate data
        match = pattern.match(route[1])

        if not match:
            # data did not validate successfully (serve 404 as if the url doesn't exist)
            pattern, action = self._server._error_actions[HTTP_404]

            getattr(action, self.in_headers["REQUEST_METHOD"].lower())(self)

            return

        # data validated successfully
        self.params.update(match.groupdict())

        getattr(action, self.in_headers["REQUEST_METHOD"].lower())(self)

# ----------------------------------------------------------------------------------------------------------------------

class RoutingHttpServer (HttpServer):

    def __init__ (self, routes, **kwargs):
        """
        Create a new RoutingHttpServer instance.

        @param routes (dict) A key->(validation, route) mapping.
        """

        HttpServer.__init__(self, **kwargs)

        self._routes = {}

        if type(routes) != dict:
            raise ServerException("Routes must be an instance of dict")

        # compile routes
        for script_name, details in routes.items():
            if type(script_name) != str:
                raise ServerException("Invalid route")

            if type(details) in (list, tuple):
                if type(details[0]) == str:
                    pattern       = details[0]
                    action        = details[1]
                    action_kwargs = dict()

                    if len(details) == 3:
                        action_kwargs = details[2]

                else:
                    pattern       = None
                    action        = details[0]
                    action_kwargs = dict()

                    if len(details) == 2:
                        action_kwargs = details[1]

                try:
                    if not issubclass(action, HttpAction):
                        raise ServerException("Action for route '%s' must be a sub-class of HttpAction" % script_name)

                except ServerException:
                    raise

                except Exception, e:
                    raise ServerException("Action for route '%s' must be a sub-class of HttpAction" % script_name)

                if pattern:
                    # this route requires a pattern
                    if type(pattern) != str:
                        raise ServerException("Regex pattern for route '%s' must be a string" % script_name)

                    try:
                        # take simplified group names and convert them to regex-style group names
                        for match in re.findall("\((?P<name>[^:]+):(?P<pattern>.*?)(?<!\\\)\)", pattern, re.I):
                            pattern = pattern.replace("(%s:%s)" % match, "(?P<%s>%s)" % match)

                        pattern = re.compile(pattern)

                    except Exception, e:
                        raise ServerException("Regex pattern error for route '%s': %s" % (script_name, str(e)))

                    try:
                        self._routes[script_name] = (pattern, action(server=self, title="Method Not Supported",
                                                                     response_code=HTTP_405, **action_kwargs))

                    except Exception, e:
                        raise ServerException("Action for route '%s' failed to instantiate: %s" % (script_name,
                                                                                                   str(e)))

                else:
                    # no pattern for this route
                    try:
                        self._routes[script_name] = (None, action(server=self, title="Method Not Supported",
                                                                  response_code=HTTP_405, **action_kwargs))

                    except Exception, e:
                        raise ServerException("Action for route '%s' failed to instantiate: %s" % (script_name, str(e)))

            else:
                raise ServerException("Route details must be a tuple or list for route '%s'" % script_name)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_client (self, client_socket, client_address, server_address):
        """
        Register a new RoutingHttpClient instance.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  A two-part tuple containing the client ip and port.
        @param server_address (tuple)  A two-part tuple containing the server ip and port to which the client has
                                       made a connection.
        """

        self.register_client(RoutingHttpClient(client_socket, client_address, self, server_address))

# ----------------------------------------------------------------------------------------------------------------------

class StaticHttpAction (HttpAction):

    def __init__ (self, fs_root, param="file", **kwargs):
        """
        Create a new StaticHttpAction instance.

        @param fs_root (str) The absolute filesystem path from which all static files will be served.
        @param param   (str) The parameter name to pull that contains the filename to serve.
        """

        HttpAction.__init__(self, **kwargs)

        self._fs_root = fs_root
        self._param   = param

    # ------------------------------------------------------------------------------------------------------------------

    def get (self, client):
        """
        Handle a GET request.

        @param client (HttpClient) The HttpClient instance.
        """

        file = os.path.realpath("/".join((self._fs_root, client.params.get(self._param, "").strip(" /\\"))))

        if not file.startswith(self._fs_root) or file == self._fs_root or not client.serve_static_file(file):
            # wrong location or file doesn't exist/can't be opened for reading
            client._server._error_actions[HTTP_404][1].get(client)
