#!/usr/bin/python
import dns.resolver
import socket
_instance = None 
__all__ = ['DNSResolverCheck', 'resolve_my_dns']

def _get_instance():
    global _instance 
    if _instance is None:
        _instance = DNSResolverCheck()
    return _instance

def resolve_my_dns():
    return _get_instance().check_my_dns()

class DNSResolverCheck(object):
    def check_my_dns(self):
        return self.dnsresolver()
    __call__ = check_my_dns
    @staticmethod
    def dnsresolver():
        blk_db = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "virbl.dnsbl.bit.nl", "dnsbl.inps.de","ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net","xbl.spamhaus.org", "pbl.spamhaus.org", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net", "db.wpbl.info"]
        my_ip = raw_input("Enter the domain you want to check \n")
        res = []
        for url in blk_db:
            my_dns = socket.gethostbyname(str(my_ip))
            try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(my_dns).split('.')))+"."+url
                answers = my_resolver.query(query,"A")
                answer_txt = my_resolver.query(query, "TXT")
                retval =  "IP %s is listed on %s (%s: %s)" %(my_dns, url, answers[0],answer_txt[0])
                res.append(retval.strip())
            except dns.resolver.NXDOMAIN:
                listed =  "IP %s is not listed in %s" %(my_dns, url)
                res.append(listed.strip())
        return res