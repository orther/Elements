# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# Author:  Sean Kerr <sean@code-box.org>
# Version: $Id$

class ElementsException (Exception):

    pass

# ----------------------------------------------------------------------------------------------------------------------
# ELEMENTS.ASYNC EXCEPTIONS
# ----------------------------------------------------------------------------------------------------------------------

class AsyncException (ElementsException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class ChannelException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class ClientException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class EventException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class HostException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class ProtocolException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class ServerException (AsyncException):

    pass

# ----------------------------------------------------------------------------------------------------------------------
# ELEMENTS.ASYNC.IMPL EXCEPTIONS
# ----------------------------------------------------------------------------------------------------------------------

class HttpException (ProtocolException):

    pass

# ----------------------------------------------------------------------------------------------------------------------
# ELEMENTS.MODEL EXCEPTIONS
# ----------------------------------------------------------------------------------------------------------------------

class ModelException (ElementsException):

    pass

# ----------------------------------------------------------------------------------------------------------------------

class DatabaseModelException (ModelException):

    pass
