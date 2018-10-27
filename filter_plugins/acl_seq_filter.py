#!/usr/bin/python
from socket import inet_aton,inet_ntoa
import struct
import operator
import re

__author__ = "Andrew Grabbs"
__credits__ = ["Andrew Grabbs"]
__version__ = "1.0.1"
__maintainer__ = "Andrew Grabbs"
__email__ = "andrew@andrewgrabbs.com"
__status__ = "Production"

class FilterModule(object):

  def filters(self):
    return {
      'acl_seq_filter': self.acl_seq_filter
    }
  def ip2long(self, ip):
    packedIP = inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

  def long2ip(self, lng):
    packed = struct.pack("!L", lng)
    ip=inet_ntoa(packed)
    return ip

  def acl_seq_filter(self, needle, haystack):
    exact = re.findall('(\d+).*?({})'.format(needle), haystack)
    if exact:
      return 666
    haystack = re.findall('(\d+).*?((?:\d+\.){3}\d+)', haystack)
    haydict = dict((k, self.ip2long(v)) for k, v in haystack)
    haydict["key"] = self.ip2long(needle)
    sort_list = sorted(haydict.items(), key=operator.itemgetter(1))
    haypos = [y[0] for y in sort_list].index('key')
    if haypos == 0:
      seq = int(sort_list[haypos + 1][0]) - 1
    else:
      seq = int(sort_list[haypos - 1][0]) + 1
    return seq
