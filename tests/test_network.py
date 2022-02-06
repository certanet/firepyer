from unittest.mock import patch

from tests.test_fdm import TestFdm


class TestNetwork(TestFdm):
    @patch('firepyer.requests.request')
    def test_get_network_objects(self, mock_request):
        """Test that the system-defined any-ipv4 NetworkObject exists
        """
        mock_request.return_value.json.return_value = {'items': [{'name': 'any-ipv4'}]}
        group = self.fdm.get_net_objects('any-ipv4')

        self.assertEqual(group['name'], 'any-ipv4', "Should find default object")
