import urllib.request
import sys
import os
import re
import ipaddress

def restart_squid():
    try:        
        os.popen("/usr/bin/sudo /usr/bin/systemctl reload squid")
        print("squid service started successfully...")
    except OSError as ose:
        print("Error while running the command", ose)
    pass
#update lists    
def update_mal_url_list():    
    block_lists = "/home/debian/netguardian/static/malicious_url_lists.txt"
    #block_lists = list
    with open ("/home/debian/netguardian/static/bad_url_sites.txt", 'w') as mal_sites:
        pass
    with open (block_lists) as mal:
        for url in mal:
            if (re.search("http://", url)) or (re.search("https://", url)):
                with urllib.request.urlopen(url) as response:
                    list = (response.read()).decode()
                    with open ("/home/debian/netguardian/static/bad_url_sites.txt", 'a+') as mal_sites:
                        mal_sites.write(list)
                        #mal_sites.close()
    validate_url_lists()
    #restart_squid()
    return
##unique and valid http/https or IPs ##
def validate_url_lists(): 
    uniq_lines = set() 

    b_list = "/home/debian/netguardian/static/bad_url_sites.txt"
    with open(b_list, 'r') as in_file:
        for line in in_file:
            if re.search("local", line): 
                continue
            elif ((re.search("http://", line) and line not in uniq_lines)): 
                uniq_lines.add(line)
            elif ((re.search("https://", line) and line not in uniq_lines)): 
                uniq_lines.add(line)
            
            elif re.search('127.0.0.1', line): 
                uniq_lines.add(line.split('127.0.0.1')[1].lstrip())
            elif re.search('0.0.0.0', line): 
                uniq_lines.add(line.split('0.0.0.0')[1].lstrip())  
            
                
    with open("/home/debian/netguardian/static/bad_urls.txt", "w") as url_out_file:
        url_out_file.writelines(uniq_lines)
    return
##update bad IP lists
def update_mal_ip_list():    
    block_lists = "/home/debian/netguardian/static/malicious_ip_lists.txt"
    with open (block_lists) as mal:
        for url in mal:
            if (re.search("http://", url)) or (re.search("https://", url)):
                with urllib.request.urlopen(url) as response:
                    list = (response.read()).decode()
                    with open ("/home/debian/netguardian/static/bad_ip_sites.txt", 'a+') as mal_sites:
                        mal_sites.write(list)
                        #mal_sites.close()
    validate_ip_lists()
    #restart_squid()
    return
## validate IP list for uniq and valid IPs
def validate_ip_lists(): 

    uniq_ips = set()
    b_list = "/home/debian/netguardian/static/bad_ip_sites.txt"
    with open(b_list, 'r') as in_file:
        for line in in_file:
            if re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", line): #validate IP format and put them in IP blocklist acl
                uniq_ips.add(line)
    with open("/home/debian/netguardian/static/bad_ip.txt", "w") as ip_out_file:
        ip_out_file.writelines(uniq_ips)
        #ip_out_file.close()

ip_list_file = "/home/debian/netguardian/static/malicious_ip_lists.txt"
url_list_file = "/home/debian/netguardian/static/malicious_url_lists.txt"
update_mal_url_list()
update_mal_ip_list()
#update program
restart_squid()
