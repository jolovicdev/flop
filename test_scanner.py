import unittest
from unittest.mock import patch, mock_open, MagicMock
import concurrent.futures
from scanner import PortScanner, generate_html_report
from datetime import datetime

class TestPortScanner(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='{"ports": {"80": {"description": "HTTP"}}}')
    @patch('os.path.join', return_value='ports.json')
    def test_init(self, mock_path_join, mock_open_file):
        scanner = PortScanner()
        self.assertIn("80", scanner.ports_data)
        self.assertEqual(scanner.ports_data["80"]["description"], "HTTP")

    @patch('builtins.open', new_callable=mock_open, read_data='{"ports": {"80": {"description": "HTTP"}}}')
    @patch('os.path.join', return_value='ports.json')
    def test_get_service(self, mock_path_join, mock_open_file):
        scanner = PortScanner()
        service = scanner.get_service(80)
        self.assertEqual(service, "HTTP")
        service = scanner.get_service(9999)
        self.assertEqual(service, "Unknown")

    @patch('socket.socket')
    @patch('builtins.open', new_callable=mock_open, read_data='{"ports": {"80": {"description": "HTTP"}}}')
    @patch('os.path.join', return_value='ports.json')
    def test_check_port_open(self, mock_path_join, mock_open_file, mock_socket):
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.connect_ex.return_value = 0
        scanner = PortScanner()
        result = scanner.check_port('google.com', 80)
        self.assertEqual(result['status'], 'OPEN')
        self.assertEqual(result['service'], 'HTTP')

    @patch('socket.socket')
    @patch('builtins.open', new_callable=mock_open, read_data='{"ports": {"80": {"description": "HTTP"}}}')
    @patch('os.path.join', return_value='ports.json')
    def test_check_port_closed(self, mock_path_join, mock_open_file, mock_socket):
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.connect_ex.return_value = 1
        scanner = PortScanner()
        result = scanner.check_port('google.com', 80)
        self.assertEqual(result['status'], 'CLOSED')
        self.assertEqual(result['service'], 'HTTP')

    @patch('concurrent.futures.ThreadPoolExecutor')
    @patch('builtins.open', new_callable=mock_open, read_data='{"ports": {"80": {"description": "HTTP"}}}')
    @patch('os.path.join', return_value='ports.json')
    def test_scan(self, mock_path_join, mock_open_file, mock_executor):
        scanner = PortScanner()
        
        # Create a mock future
        mock_future = MagicMock(spec=concurrent.futures.Future)
        mock_future.result.return_value = {'port': 80, 'status': 'OPEN', 'service': 'HTTP'}
        
        # Create a mock executor instance
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        
        # Make submit return our mock future
        mock_executor_instance.submit.return_value = mock_future
        
        # Create a dictionary that maps our mock future to a port number
        future_to_port = {mock_future: 80}
        
        # Mock as_completed to return our mock future
        def mock_as_completed(futures_dict):
            return [mock_future]
            
        with patch('concurrent.futures.as_completed', side_effect=mock_as_completed):
            results = scanner.scan('google.com', start_port=80, end_port=80, threads=1)
        
        # Verify the results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['port'], 80)
        self.assertEqual(results[0]['status'], 'OPEN')
        self.assertEqual(results[0]['service'], 'HTTP')
        
        # Verify submit was called with correct arguments
        mock_executor_instance.submit.assert_called_with(
            scanner.check_port, 'google.com', 80
        )

class TestGenerateHtmlReport(unittest.TestCase):
    def test_generate_html_report(self):
        results = [{'port': 80, 'status': 'OPEN', 'service': 'HTTP'}]
        host = 'google.com'
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime(2023, 1, 1, 12, 0, 10)
        html = generate_html_report(results, host, start_time, end_time)
        self.assertIn('<title>Port Scan Report - google.com</title>', html)
        self.assertIn('<td>80</td>', html)
        self.assertIn('<td>OPEN</td>', html)
        self.assertIn('<td>HTTP</td>', html)

if __name__ == '__main__':
    unittest.main()