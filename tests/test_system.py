from unittest.mock import patch

from tests.test_fdm import TestFdm


class TestSystem(TestFdm):
    @patch('firepyer.requests.request')
    def test_system_info(self, mock_request):
        """Test system info
        """
        mock_request.return_value.json.return_value = {'type': 'systeminformation'}
        response = self.fdm.get_system_info()

        self.assertEqual(response['type'], 'systeminformation')
