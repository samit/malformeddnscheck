#!/usr/bin/python
import commands
_instance  = None
__all__ = ['ScanTypes','udp_empty_packets','tcp_flag_scan']

def _get_instance():
    global _instance
    if _instance is None:
        _instance = ScanTypes()
    return _instance

def udp_empty_packets():
    return _get_instance().empty_packets_scan()

def tcp_flag_scan():
    return _get_instance().tcp_syn_packets()

class ScanTypes(object):
    def empty_packets_scan(self):
        return self.udp_empty_scan(self.get_target_host())
    __call__ = empty_packets_scan
    @staticmethod
    def udp_empty_scan(host):
        comm = commands.getoutput("sudo nmap -sU "+host)
        return comm
    
    @staticmethod
    def get_target_host():
        host = raw_input("Enter the target host")
        return host

    def tcp_syn_packets(self):
        return self.tcp_flag_scan(self.get_target_host(), self.get_scan_flags())
    __call__ = tcp_syn_packets
    @staticmethod
    def tcp_flag_scan(host, scanflags):
        comm = commands.getoutput("sudo nmap --scanflags "+scanflags+" "+host)
        return comm 
    @staticmethod
    def get_scan_flags():
        flags = raw_input("Enter the scan flags")
        return flags