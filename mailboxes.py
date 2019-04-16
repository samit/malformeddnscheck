#!/usr/bin/python
from selenium import webdriver
import time, socket, re, commands
from selenium.webdriver.support.ui import Select
from selenium.webdriver.chrome.options import Options
options = Options()
options.add_argument("--headless")

_instance = None
browser = webdriver.Chrome(options=options)


__all__ = ['MailboxCheckup', 'verify_against_blacklist' ,'threat_db','emerging_threat', 'alienvault_db']
URL = 'http://multirbl.valli.org/'
def _get_instance():
    global _instance
    if _instance is None:
        _instance = MailboxCheckup()
    return _instance

def verify_against_blacklist():
    return _get_instance().check_malware_host()
def threat_db():
    return _get_instance().get_compare_malware_list()

def emerging_threat():
    return _get_instance().get_emerging_threat_db()

def alienvault_db():
    return _get_instance().get_alienvault_db()

class MailboxCheckup(object):
    def __init__(self, url=URL):
        self.url=url
    
    def get_emerging_threat_db(self):
        return self.emergingdb()
    __call__ = get_emerging_threat_db

    @staticmethod
    def emergingdb():
        pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        emerging_list = ['http://rules.emergingthreats.net/open/suricata/rules/botcc.rules',
        'http://rules.emergingthreats.net/open/suricata/rules/tor.rules']
        for query in emerging_list:
            comm = commands.getoutput('curl '+query)
            emerging_result = re.findall(pattern, comm)
        my_ip = socket.gethostbyname('mail.apf.gov.np')
        for ip in emerging_result:
            if my_ip == ip:
                return_string = "You are blacklisted on emerging threat db"
                return return_string
        return "You are not a malware host at emerging db"
    
    def get_alienvault_db(self):
        return self.alienvault_db()
    
    __call__ = get_alienvault_db

    @staticmethod
    def alienvault_db():
        comm = commands.getoutput("curl http://reputation.alienvault.com/reputation.generic")
        pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        alien_result = re.findall(pattern,comm)
        my_ip = socket.gethostbyname('mail.apf.gov.np')
        for ip in alien_result:
            if my_ip == ip:
                return "your ip is found on alienvault threat intel db"
        return "Hurray your ip have good reputation from alien vault"
    
    def check_malware_host(self):
        return self.verify_mailserver(self.url)
    
    __call__ = check_malware_host

    
    def get_compare_malware_list(self):
        return self.compare_against_threat_intel_db()
    __call__ = get_compare_malware_list

    @staticmethod
    def compare_against_threat_intel_db():
        threat_db_list = ['http://labs.snort.org/feeds/ip-filter.blf','http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt',
        'http://www.malwaredomainlist.com/hostslist/ip.txt','http://www.ciarmy.com/list/ci-badguys.txt'
        ]
        print "Malware host will be tested against following threat intel db \n"

        for url in threat_db_list: 
            print url+"\n" 
            browser.get(url)
            ip_list = browser.find_element_by_xpath('/html/body')
            ip_list = ip_list.text.split()
            my_ip = socket.gethostbyname('mail.apf.gov.np')
            for ip in ip_list:
                if my_ip == ip:
                    return "i am blacklisted "+url
        return "Not blacklisted"


    @staticmethod
    def verify_mailserver(mxcheckapi):
        response_data = []
        browser.get(URL)
        input_element = browser.find_element_by_xpath('//*[@id="qform"]/div[2]/div[2]/input')
        host_name = raw_input("Please ENter the host or IP to check \n")
        input_element.send_keys(host_name)
        browser.find_element_by_xpath('//*[@id="qform"]/div[3]/div[2]/input').click()
        mxquery = browser.find_element_by_xpath('//*[@id="lo-main"]/table[1]')
        for row in mxquery.find_elements_by_xpath(".//tr"):
            data = [td.text for td in row.find_elements_by_xpath("//*[starts-with(@id, 'DNSBLBlacklistTest_')]")]
            combinedlist = [td.text for td in row.find_elements_by_xpath("//*[starts-with(@id, 'DNSBLCombinedlistTest_')]")]
            whitelist = [td.text for td in row.find_elements_by_xpath("//*[starts-with(@id, 'DNSBLWhitelistTest_')]")]
        for x in data:
            response_data.append(x)
        for x in combinedlist:    
            response_data.append(x)
        for x in whitelist:    
            response_data.append(x)
        result =[td.text for td in row.find_elements_by_xpath('//*[@id="lo-main"]/table[1]/tbody/tr')]
        for x in result:
            response_data.append(x)
        browser.close()
        return response_data
        
