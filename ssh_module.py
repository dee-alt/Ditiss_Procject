#!/usr/bin/python3
import fileinput
import re
import os
import stat
file_name="/etc/ssh/sshd_config"

def permission():
	uid=os.getuid()
	gid=os.getgid()
	if uid==0 and gid==0:
		os.chmod(file_name,stat.S_IRUSR | stat.S_IWUSR)
	else:
		print("Not a Root User")

def protocol():
	f=open(file_name,"a+")
	f.write("Protocol 2")

def replace():
	for line in fileinput.FileInput(file_name,inplace=1):
		if "PermitRootLogin" in line:
			line=line.rstrip()
			line=line.replace("yes","no")
		if "#LogLevel" in line:
			line=line.rstrip()
			line=line.replace("#LogLevel INFO","LogLevel INFO")
		if "X11Forwarding" in line:
			line=line.rstrip()
			line=line.replace("yes","no")
		if "MaxAuthTries" in line:
			line=re.sub(r'#*MaxAuthTries\s[\d]*.','MaxAuthTries 4',line)
		if "IgnoreRhosts" in line:
			line=re.sub(r'#*IgnoreRhosts\s.*','IgnoreRhosts yes',line)
		if "HostbasedAuthentication" in line:
			line=re.sub(r'#HostbasedAuthentication\s.*','HostbasedAuthentication no',line)
		if "PermitEmptyPasswords" in line:
			line=re.sub(r'#PermitEmptyPasswords\s.*','PermitEmptyPasswords no',line)
		if "PermitUserEnvironment" in line:
                        line=re.sub(r'#PermitUserEnvironment\s.*','PermitUserEnvironment no',line)
		if "ClientAliveInterval" in line:
			line=re.sub(r'#*ClientAliveInterval\s[\d]*','ClientAliveInterval 300',line)
		if "ClientAliveCountMax" in line:
			line=re.sub(r'#*ClientAliveCountMax\s[\d]*','ClientAliveCountMax 0',line)
		if "LoginGraceTime" in line:
			line=re.sub(r'#*LoginGraceTime\s[\d]*.','LoginGraceTime 60',line)
		if "Banner" in line:
			line=re.sub(r'#*Banner\s.*','Banner /etc/issue.net',line)
			os.system('systemctl restart sshd')
		
		line=line.strip()
		print(line)

if __name__ == '__main__':
	permission()
	protocol()
	replace()

