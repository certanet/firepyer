class FirepyerError(Exception):
    def __init__(self, message) -> None:
        super().__init__(message)


class AuthError(FirepyerError):
    """Raised when the FTD rejects the username/password authentication
    """
    pass


class ResourceNotFound(FirepyerError):
    """Raised when an object by a given name or ID cannot be found in the FTD config
    """
    pass


class UnreachableError(FirepyerError):
    """Raised when the IP or hostname of the FTD device is unreachable
    """
    pass
