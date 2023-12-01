from flask import Flask, render_template, request, url_for, flash, redirect, jsonify
import re, time, os
import urllib.request
import sys, subprocess
import ipaddress
#from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

app.config['SECRET_KEY'] = '826cde75bf5d08970db925d4974c0cfb245233b79c46446e'

messages = [{'title': 'Message One',
             'content': 'Message One Content'},
            {'title': 'Message Two',
             'content': 'Message Two Content'}
            ]

###################################################
## update whitelist/blacklist/malicious lists    ##
###################################################

def update_list(orig_file, row):
    rows = open(orig_file, 'r').readlines()
    rows[row] = '\n'
    updated_file = open(orig_file, 'w')
    updated_file.writelines(rows)
    updated_file.close()
    cleanup_blanks(orig_file)
    return

#update lists to reflect whitelist
def update_whitelist(orig_file, line):
    rows = open(orig_file, 'r').readlines()
    with open (orig_file, "w") as new_file:
        
        for idx, row in enumerate(rows):
            if row.strip("\n") == line:
                #print("found: ", row, "content", rows)
                rows[idx] = "\n"
        new_file.writelines(rows)
    cleanup_blanks(orig_file)    
    #updated_file = open(orig_file, 'w')
    #updated_file.writelines(rows)
    #updated_file.close()
    return
#cleanup blank lines in file
def cleanup_blanks(list_file):
    with open(list_file) as reader, open(list_file, 'r+') as writer:
        for line in reader:
            if line.strip():
                writer.write(line)
        writer.truncate()
        writer.close()
####
###Update Log options#####
def _update_log_options(proxy_file, option):
    rows = open(proxy_file, 'r').readlines()
    for row, line in enumerate (rows):
        
        if(re.search("success.log.txt", line)) and option == "no":
            rows[row] = "#access_log stdio:/var/log/squid/success.log.txt logformat=guardian success\n"
            break
        if(re.search("success.log.txt", line)) and option == "yes":
            rows[row] = "access_log stdio:/var/log/squid/success.log.txt logformat=guardian success\n"     
            break
        else:
            pass
    with open(proxy_file, 'w+') as writer:        
        writer.writelines(rows)
        writer.close()

###
def update_mal_url_list(list):    
    #block_lists = "/home/debian/netguardian/static/malicious_list.txt"
    block_lists = list
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
    return
##unique and valid http/https or IPs ##
def validate_url_lists(badlist): 
    uniq_lines = set() 

    b_list = badlist
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
def update_mal_iplist(list):    
    block_lists = list
    with open (block_lists) as mal:
        for url in mal:
            if (re.search("http://", url)) or (re.search("https://", url)):
                with urllib.request.urlopen(url) as response:
                    list = (response.read()).decode()
                    with open ("/home/debian/netguardian/static/bad_ip_sites.txt", 'a+') as mal_sites:
                        mal_sites.write(list)
                        #mal_sites.close()
    return
## validate IP list for uniq and valid IPs
def validate_ip_lists(badlist): 

    uniq_ips = set()
    b_list = badlist
    with open(b_list, 'r') as in_file:
        for line in in_file:
            if re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", line): #validate IP format and put them in IP blocklist acl
                uniq_ips.add(line)
    with open("/home/debian/netguardian/static/bad_ip.txt", "w") as ip_out_file:
        ip_out_file.writelines(uniq_ips)
        #ip_out_file.close()

#URL list size info
def url_entries():
    rows = open("/home/debian/netguardian/static/bad_urls.txt", 'r').readlines()
    with open("/home/debian/netguardian/static/url_list_size.txt", "w") as url_list_size:
        url_list_size.write("Total number of URL entries: "+str(len(rows)))
      
#IP list size
def ip_entries():
    rows = open("/home/debian/netguardian/static/bad_ip.txt", 'r').readlines()
    with open("/home/debian/netguardian/static/ip_list_size.txt", "w") as ip_list_size:
        ip_list_size.write("Total number of IP entries: "+str(len(rows)))
    

## restart services ##

## nginx Service Restart function ##
def restart_nginx():
    try:        
        os.popen("/usr/bin/sudo /usr/bin/systemctl restart nginx")
        print("nginx service started successfully...")
    except OSError as ose:
        print("Error while running the command", ose)
    pass

## guardian Service Restart function ##
def restart_guardian():
    try:        
        os.popen("/usr/bin/sudo /usr/bin/systemctl restart guardian")
        print("guardian service started successfully...")
    except OSError as ose:
        print("Error while running the command", ose)
    pass

def _restart_squid():
    try:        
        os.popen("/usr/bin/sudo /usr/bin/systemctl restart squid")
        #print("squid service started successfully...")
        time.sleep(40)
        #return "system updated successfully..."
        return
    except OSError as ose:
        return "Error while running the command"+ose
    pass

def restart_squid():
    try:        
        proc=subprocess.run("/usr/bin/sudo /usr/bin/systemctl reload squid", shell=True, stdout=subprocess.PIPE, )
        #proc.wait()
        status=subprocess.Popen('/usr/bin/sudo /usr/bin/systemctl status squid', shell=True, stdout=subprocess.PIPE, )
        output=status.communicate()[0]
        if(re.search('running', output.decode())):
            return "system updated successfully..."
    except OSError as ose:
        return "Error while updating the system"
    pass

#########
#main menu options

@app.route('/')
def index():
    return render_template('index.html', messages=messages)

@app.route('/feedback/', methods=('GET', 'POST'))
def feedback():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        email = request.form['email']

        if not title:
            flash('Name is required!')
        elif not email:
            flash('Email is required!')
        elif not content:
            flash('Message is required!')
        else:
            messages.append({'title': title, 'content': content})
            with open('/home/debian/netguardian/static/feedback.txt', 'a+') as feedback:
                feedback.write('Name:'+title+'\t Email:'+email+'\n \tFeedback:'+content+'\n\n')
            return redirect(url_for('feedback'))

    return render_template('feedback.html')

###Whitelist
@app.route('/whitelist/', methods=('GET', 'POST'))
def whitelist():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        #list_file = "/var/www/guardian/html/whitelist.txt"
        list_file = "/home/debian/netguardian/static/allowed_list.txt"
        blacklist = "/home/debian/netguardian/static/blocked_list.txt"
        mali_ip_list = "/home/debian/netguardian/static/bad_ip.txt"
        mali_url_list = "/home/debian/netguardian/static/bad_urls.txt"
        if not content:
            flash('URL is required!')
        elif title == 'Remove':
            with open(list_file, 'r') as white:
                for row, line in enumerate(white):
                    if re.search(content, line):
                        update_list(list_file, row)
                #flash("List updated")

            #return redirect(url_for('whitelist'))
        elif title == 'Add':
            #print("URL: ", content, "option: ", title)
            with open(list_file, 'a') as white:
                white.write('\n'+content+'\n')
            update_whitelist(blacklist, content)
            update_whitelist(mali_ip_list, content)
            update_whitelist(mali_url_list, content)
            cleanup_blanks(list_file)
            #flash("List updated")
            #return redirect(url_for('whitelist'))
        restart_squid()
        flash("List updated")
        return redirect(url_for('whitelist'))
    return render_template('whitelist.html')
    #return render_template('index.html')
 
 ###Blacklist ##
@app.route('/blacklist/', methods=('GET', 'POST'))
def blacklist():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        list_file = "/home/debian/netguardian/static/blocked_list.txt"
        if not content:
            flash('URL is required!')
        elif title == 'Remove':
            with open(list_file, 'r') as black:
                for row, line in enumerate(black):
                    if re.search(content, line):
                        update_list(list_file, row)
                #restart_squid()
                #flash("List updated")
            #return redirect(url_for('blacklist'))
        elif title == 'Add':
            with open(list_file, 'a') as black:
                if (re.search("http://", content)): 
                    black.write('\n'+(content.split('http://')[1]))
                #domain = (content.split('http://')[1])
                elif (re.search("https://", content)): 
                    black.write('\n'+(content.split('https://')[1]))
                else:
                    black.write('\n'+content+'\n')
                #domain = (content.split('https://')[1])
            #with open(list_file, 'a') as black:
                #black.write('\n'+domain)
            cleanup_blanks(list_file)
            #restart_squid()
            
            
            #return redirect(url_for('blacklist'))
        restart_squid()
        flash("List updated")
        return redirect(url_for('blacklist'))
    return render_template('blacklist.html')
    #return render_template('index.html')
###Malicious sites list ##
###Malicious sites list ##
@app.route('/mal_ip/', methods=('GET', 'POST'))
def mal_ip():
    list_file = "/home/debian/netguardian/static/malicious_ip_lists.txt"
    bad_list = "/home/debian/netguardian/static/bad_ip_sites.txt"
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not content:
            flash('URL is required!')
        elif title == 'Remove':
            with open(list_file, 'r') as mal:
                for row, line in enumerate(mal):
                    if re.search(content, line):
                        update_list(list_file, row)
            #flash("List updated")            
            #return redirect(url_for('mal_ip'))
        elif title == 'Add':
            with open(list_file, 'a') as mal:
                mal.write('\n'+content)
            cleanup_blanks(list_file)
            #flash("List updated")
            #return redirect(url_for('mal_ip'))
        update_mal_iplist(list_file)
        validate_ip_lists(bad_list)
        restart_squid()
        ip_entries()
        flash("List updated")
        return redirect(url_for('mal_ip'))
    return render_template('mal_ip.html')
@app.route('/mal_url/', methods=('GET', 'POST'))
def mal_url():
    list_file = "/home/debian/netguardian/static/malicious_url_lists.txt"
    bad_list = "/home/debian/netguardian/static/bad_url_sites.txt"
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not content:
            flash('URL is required!')
        elif title == 'Remove':
            with open(list_file, 'r') as mal:
                for row, line in enumerate(mal):
                    if re.search(content, line):
                        update_list(list_file, row)
            #return redirect(url_for('mal_url'))
        elif title == 'Add':
            with open(list_file, 'a') as mal:
                mal.write('\n'+content)
            cleanup_blanks(list_file)
            
            #return redirect(url_for('mal_url'))
        update_mal_url_list(list_file)
        validate_url_lists(bad_list)
        restart_squid()
        url_entries()
        flash("List updated")
        return redirect(url_for('mal_url'))
    return render_template('mal_url.html')

## reputation check ##
@app.route('/reputation_check')
def reputation_check():
    return render_template('reputation_check.html', messages=messages)
    
## Logs ##
@app.route('/logs')
def logs():
    with open("/var/log/squid/failure.log.txt", 'r') as log0:
        lines =  log0.readlines()
        with open("/home/debian/netguardian/static/current_log.txt", 'w') as cur_log:
            cur_log.writelines("".join((reversed(lines))))
    log_file = "/var/log/squid/failure.log.txt."
    for i in range(0,6):
        try:
            with open (log_file+str(i), 'r') as logfile:
                lines = logfile.readlines()
                with open ("/home/debian/netguardian/static/log_file_"+str(i)+".txt", 'w') as file:
                    file.writelines("".join((reversed(lines))))
        except:
            pass
    return render_template('logs.html')    

@app.route('/allowed_logs')
def allowed_logs():
    with open("/var/log/squid/success.log.txt", 'r') as log0:
        lines =  log0.readlines()
        with open("/home/debian/netguardian/static/current_a_log.txt", 'w') as cur_log:
            cur_log.writelines("".join((reversed(lines))))
    log_file = "/var/log/squid/success.log.txt."
    for i in range(0,6):
        try:
            with open (log_file+str(i), 'r') as logfile:
                lines = logfile.readlines()
                with open ("/home/debian/netguardian/static/a_log_file_"+str(i)+".txt", 'w') as file:
                    file.writelines("".join((reversed(lines))))
        except:
            pass
    return render_template('allowed_logs.html')    
    
@app.route('/help')
def help():
    return render_template('help.html')
@app.route('/docs')
def docs():
    return render_template('docs.html')    
@app.route('/about')
def about():
    return render_template('about.html') 
    
@app.route('/system/', methods=('GET', 'POST'))
def system():
    url_list_file = "/home/debian/netguardian/static/malicious_url_lists.txt"
    url_bad_list = "/home/debian/netguardian/static/bad_url_sites.txt"
    ip_list_file = "/home/debian/netguardian/static/malicious_ip_lists.txt"
    ip_bad_list = "/home/debian/netguardian/static/bad_ip_sites.txt"
    if request.method == 'POST':
        title = request.form['title']
        #blacklist = request.form['title2']
        #IP_blacklist = request.form['title3']
        #URL_blacklist = request.form['title4']
        #content = request.form['content']
        
        if title == "no":
            flash('No changes!')
        elif title =="yes":
            
            update_mal_url_list(url_list_file)
            validate_url_lists(url_bad_list)
            update_mal_iplist(ip_list_file)
            validate_ip_lists(ip_bad_list)
            restart_squid()
            flash('IP/URL lists are refreshed!')
            return redirect(url_for('system'))
    return render_template('system.html')

@app.route('/log_options/', methods=('GET', 'POST'))
def log_options():
    proxy_file = "/etc/squid/squid.conf"
    
    if request.method == 'POST':
        title = request.form['title']
               
        if title == "no":
            #option = "no"
            proc=subprocess.run("/usr/bin/sudo python3 /home/debian/netguardian/disable_success_logs.py", shell=True, stdout=subprocess.PIPE, )
            #update_log_options(proxy_file, option)
            os.system("/usr/bin/sudo rm /var/log/squid/success.log.*")
            #os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.0")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.1")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.2")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.3") 
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.4")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.5")
            os.system("/usr/bin/rm /home/netguardian/static/a_log_file.*")
            os.system("/usr/bin/rm /home/netguardian/static/current_a_log.txt")
            os.system("/usr/bin/touch /home/netguardian/static/current_a_log.txt")
            restart_squid()
            flash('Allowed site Logs will not be captured and shown!')
        elif title =="yes":
            option = "yes"
            proc=subprocess.run("/usr/bin/sudo python3 /home/debian/netguardian/enable_success_logs.py", shell=True, stdout=subprocess.PIPE, )
            #update_log_options(proxy_file, option)
            os.system("/usr/bin/sudo rm /var/log/squid/success.log.*")
            #os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.0")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.1")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.2")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.3") 
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.4")
            os.system("/usr/bin/sudo touch /var/log/squid/success.log.txt.5")
            os.system("/usr/bin/rm /home/netguardian/static/a_log_file.*")
            os.system("/usr/bin/rm /home/netguardian/static/current_a_log.txt")
            os.system("/usr/bin/touch /home/netguardian/static/current_a_log.txt")
            
            restart_squid()
            flash('Allowed site Logs will be captured from now and shown!')
            #return redirect(url_for('log_options'))
    return render_template('log_options.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0')    
    #app.run(debug=True)
    #app.run(host='0.0.0.0', debug=True, ssl_context=context)
