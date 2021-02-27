class FirepyerError(Exception):
    """Raised if no more-specific exception applies, such as errors presented directly from FTD
    """
    def __init__(self, message) -> None:
        super().__init__(message)


class FirepyerAuthError(FirepyerError):
    """Raised when the FTD rejects the username/password authentication
    """
    pass


class FirepyerInvalidOption(FirepyerError):
    """Raised when the value provided does not match the set of predefined options
    """
    pass


class FirepyerResourceNotFound(FirepyerError):
    """Raised when an object by a given name or ID cannot be found in the FTD config
    """
    pass


class FirepyerUnreachableError(FirepyerError):
    """Raised when the IP or hostname of the FTD device is unreachable
    """
    pass
