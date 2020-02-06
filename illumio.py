import csv
import ipaddress
from collections import defaultdict

class RuleEngine:
  def __init__(self):
    """
      The rule-engine represents the rules in the form of a trie.
    """
    self.trie = {
      'inbound': {'tcp': defaultdict(list), 'udp': defaultdict(list)},
      'outbound': {'tcp': defaultdict(list), 'udp': defaultdict(list)}
    }


  def _ip_range_handler(self, direction, protocol, port, ip_addr):
    """
      Handles the addition of ip address to the trie. Each port is attached
      to a range of ip addresses.
    """
    if '-' in ip_addr: # if the ip is in the form of a range
      # IP addresses are represented as integers in the trie
      lrange, rrange = map(ipaddress.IPv4Address, ip_addr.split('-'))
      lrange, rrange = int(lrange), int(rrange) + 1

      for _ip in range(lrange, rrange):
        self.trie[direction][protocol][port].append(_ip)
    else:
      self.trie[direction][protocol][port].append(int(ipaddress.IPv4Address(ip_addr)))


  def _port_range_handler(self, direction, protocol, port, ip_addr):
    """
      Handles the addition of the ports to the trie.
    """
    if '-' in port: # if the port is in the form of a range
      lrange, rrange = map(int, port.split('-'))
      for port_i in range(lrange, rrange + 1):
        self._ip_range_handler(direction, protocol, port_i, ip_addr)
    else:
      self._ip_range_handler(direction, protocol, int(port), ip_addr)


  def construct_lookup_tree(self, data):
    """
      This routine represents merely an abstraction for construction of the tree.
    """
    self._port_range_handler(*data)



class Firewall(RuleEngine):
  """
    Firewall inherits the trie from the RuleEngine.
  """
  def __init__(self, path_to_rules_csv):
    super().__init__()
    with open(path_to_rules_csv, 'r') as f:
      for data in csv.reader(f):
        # use each line of the ruleset to create a rule trie
        self.construct_lookup_tree(data)


  def accept_packet(self, direction, protocol, port, ip_address):
    try: # throws an error if the port, protocol, or the direction doesn't exist
      if int(ipaddress.IPv4Address(ip_address)) in self.trie[direction][protocol][port]:
        return True
    except:
      return False
    
    return False

