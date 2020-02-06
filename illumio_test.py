import unittest
from illumio import Firewall

class TestFirewall(unittest.TestCase):

  def setUp(self):
    self.fw = Firewall('./illumio_data.csv')

  def test_0(self):
    self.assertEqual(self.fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"), True)

  def test_1(self):
    self.assertEqual(self.fw.accept_packet("inbound", "udp", 53, "192.168.2.1"), True)

  def test_2(self):
    self.assertEqual(self.fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"), True)

  def test_3(self):
    self.assertEqual(self.fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"), False)

  def test_4(self):
    self.assertEqual(self.fw.accept_packet("inbound", "udp", 24, "52.12.48.92"), False)

if __name__ == '__main__':
  unittest.main()
