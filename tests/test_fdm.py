import unittest

from firepyer import Fdm


class TestFdm(unittest.TestCase):
    """Base class for testing firepyer Fdm methods
    """
    def __init__(self, methodName: str) -> None:
        super().__init__(methodName=methodName)
        self.fdm = Fdm(host='192.168.45.45', username='admin', password='Admin123')
