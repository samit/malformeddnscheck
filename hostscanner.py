#!/usr/bin/python
import commands

_instance=None
__all__ = ['HostScanner', 'scan_host']

def _get_instance():
  global _instance
  if _instance is None:
    _instance = HostScanner()
  return _instance


def scan_host():
  return _get_instance().scanHost()


class HostScanner(object):
  def scanHost(self):
    return self.nmapHostScan()

  __call__ = scanHost
  @staticmethod
  def nmapHostScan():
    print "Please Enter the IP address Range for Host Discovery eg 2.2.2.2-100"
    ip_range = raw_input()
    scanner = commands.getoutput("sudo nmap -n -sP "+ip_range)
    print scanner
    return scanner

