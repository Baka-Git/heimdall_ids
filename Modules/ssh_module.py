#import paramiko
import time


#  need to install paramiko
#  pip install param
#  if problem with installing paramiko, use sudo apt install python3-pip
#  and run again

# function for executing given command via SSH
def ssh_command_execute(command, ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        #print("OK")
        # ssh.connect('10.10.152.85', username='admin', password='mikrotik')
        ssh_stdin, stdout, ssh_stderr = ssh.exec_command(command)
    except:
        return False
    return stdout


def get_mac_int_helper(list_of_line):
    for i in range(0, len(list_of_line)):
        subject = list_of_line[i]
        for ch in subject:
            if ch == ":":
                return [subject, list_of_line[i + 1]]


# help function, which filter MAC and interfaces from input and put them into dictionary
def get_mac_int(list_from_mikrotik):
    list_from_mikrotik.pop(0)
    list_from_mikrotik.pop(0)
    mac_int = {}
    blank = False
    for line in list_from_mikrotik:
        new_line = ""
        for i in range(0, len(line)):
            a = line[i]
            if a == " " and blank is False:
                new_line = new_line + ","
                blank = True
            elif a != " " and blank is True:
                blank = False
                new_line = new_line + a
            elif a != " " and blank is False:
                new_line = new_line + a
        list_help = new_line.split(",")
        a = get_mac_int_helper(list_help)
        if a is not None:
            mac_int[a[0]] = a[1]
    # print(mac_int)
    return mac_int


# function to get all MAC addresses and Interfaces from CAM table of Mikrotik router
def ssh_get_arp(ip, username, password):
    command = "interface bridge host print"
    info = ssh_command_execute(command, ip, username, password)
    help_list = []
    if info is False:
        return False
    for line in info:
        word = line.strip('\n')
        help_list.append(word)
    mac_int = get_mac_int(help_list)
    return mac_int


# function for banning interface, where attacker is, function get all MAC what are in the CAM table and if MAC of
# Attacker match with one, interface where it is will be shut down (if interface is considered as SAFE, BAN will not
# happen)

def ssh_ban(list_of_safe_int, mac_to_ban, ip, username, password):
    command = "interface ethernet disable "
    gate = True
    while gate:
        mac_int = ssh_get_arp(ip, username, password)
        if mac_int is not False:
            gate = False
        else:
            time.sleep(1)
    interface = ""
    for key in mac_int:
        if key == mac_to_ban:
            interface = mac_int[key]
    for safe_int in list_of_safe_int:
        if safe_int == interface:
            print("BAN does not happened, because interface is defined as SAFE")
            return False
    if interface =="":
        return False
    gate = True
    while gate:
        ban = ssh_command_execute(command + interface, ip, username, password)
        if ban is not False:
            gate = False
        else:
            time.sleep(1)
    print("BAN does happened")
    return True


# function for testing if SSH connection is working
def ssh_test(ip, username, password):
    try:
        ssh_command_execute("interface", ip, username, password)
    except:
        return False
    return True

# ssh_get_arp("192.168.88.1", "admin", "mikrotik")
