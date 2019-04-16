#!/isr/bin/python

import commands
_instance = None
__all__ = ['PortScanner', 'basic_scanner', 'port_list_scan','tcp_udp_port_scan']

def _get_instance():
    global _instance
    if _instance is None:
        _instance = PortScanner()
    return _instance

def basic_scanner():
    return _get_instance().nmap_basic_port_scan()

def port_list_scan():
    return _get_instance().nmap_port_list_scan()

def tcp_udp_port_scan():
    return _get_instance().nmap_tcp_udp()


class PortScanner(object):
    def nmap_basic_port_scan(self):
        return self.basic_scan()
    __call__ = nmap_basic_port_scan
    @staticmethod
    def basic_scan():
        ip = raw_input("Enter the ip address range")
        comm = commands.getoutput("sudo nmap "+ip)
        return comm
    
    def nmap_port_list_scan(self):
        return self.port_list_scan(self.get_host_list())

    __call__=nmap_port_list_scan
    @staticmethod
    def port_list_scan(host):
        return 
    @staticmethod
    def get_host_list():
        return

    def nmap_tcp_udp(self):
        return self.scan_tcp_udp(self.tcp_list(), self.udp_list())
    __call__ = nmap_tcp_udp
    @staticmethod
    def scan_tcp_udp(tcp, udp):
        return
    @staticmethod
    def tcp_list():
        return
    @staticmethod
    def udp_list():
        return
    

