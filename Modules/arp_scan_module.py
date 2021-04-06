import time
import struct
from Modules.sniffer_tools import *
from Modules.ssh_module import *
import uuid


#   helping class to store several information about one "host"
class Bond:
    def __init__(self, mac, ip, interface, verification, info):
        # Info | MAC | IP | Int | Time | Verification
        self.info = info  # information about host (New!, "", Fake!, IDS)
        self.mac = mac  # MAC address of the host
        self.ip = ip  # IP address of the host
        self.int = interface  # on which interface on Mikrotik host is
        self.timer = time.perf_counter()  # how old is last info about host
        # 0 = not verified, 1 = real, 2 = probably fake
        self.verification = verification
        if info == "IDS":
            self.timer = 0


# main class for ARP scanning
class ArpScan:
    def __init__(self, list_of_ips, interval_send, much, ssh_info):
        self.ssh_info = ssh_info  # information about SSH connection to verified MAC address
        self.list_of_ips = list_of_ips  # list of all IP addresses in local network which can be used
        self.timer_send = time.perf_counter()  # timer for sending arp requests
        self.timer_actual = time.perf_counter()  # timer for actualization of list of hosts
        self.point = 0  # help pointer for selecting groups of IP address for sending
        self.list_of_bonds = []  # list of known hosts
        self.interval_send = interval_send  # interval for sending one group of IP addresses
        self.much = much  # number about how many IP addresses can be in one group for sending
        self.interval_actual = len(list_of_ips) / much * interval_send * 4  # interval
        self.length_of_list = len(list_of_ips)  # length of list of all IPs in the network
        self.my_ip = get_my_ip()  # IP address of IDS
        self.my_mac = get_my_mac().upper()  # MAC address of IDS
        self.list_of_bonds.append(Bond(self.my_mac, self.my_ip, "", 1, "IDS"))  # IDS will be static in bond list

    # function for receiving ARP responses
    def arp_receive(self, data):
        mode, src_mac, src_ip = struct.unpack('! H 6s 4s', data[6:18])
        ip = get_ip_address(src_ip)
        mac = get_mac_address(src_mac)
        if self.arp_valid(ip, mode):

            self.list_update(ip, mac)

    # function  for validation if arp is response and is from group to which arp scan send arp requests
    def arp_valid(self, ip, mode):
        if mode == 2:  # response
            board = self.point + self.much
            if board >= self.length_of_list:
                board = self.length_of_list

            for i in range(self.point, board):
                if self.list_of_ips[i] == ip:
                    return True
        return False

    # function for updating list of hosts
    def list_update(self, ip, mac):
        if len(self.list_of_bonds) == 0:
            self.list_of_bonds.append(Bond(mac, ip, "", 0, "New!"))
        else:
            for bond in self.list_of_bonds:
                if bond.ip == ip and bond.mac == mac:
                    bond.timer = time.perf_counter()
                    return True
            self.list_of_bonds.append(Bond(mac, ip, "", 0, "New!"))

    # function for actualizing list of hosts in the network
    def list_actual(self):
        self.connect_mac_ip_int()
        time_is_up = time.perf_counter()
        index = 0
        for bond in self.list_of_bonds:
            if time_is_up - bond.timer > self.interval_actual and bond.info != "IDS" and bond.info != "Fake?":
                print(bond.ip)
                self.list_of_bonds.pop(index)
            index += 1

    # function for sending ARP requests for group of IP addresses
    def arp_send(self):
        if time.perf_counter() - self.timer_send > self.interval_send:
            self.point = self.point + self.much
            if self.point >= self.length_of_list:
                self.point = 0
            board = self.point + self.much
            if board >= self.length_of_list:
                board = self.length_of_list
            for ip in range(self.point, board):
                self.send(self.list_of_ips[ip])
            self.timer_send = time.perf_counter()

    # function for send request to ONE IP address
    def send(self, ip):
        # print(1)
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        raw_socket.bind(("eth0", socket.htons(0x0800)))
        source_mac = bytes(self.my_mac, encoding="raw_unicode_escape")  # sender mac address
        source_ip = self.my_ip  # sender ip address
        dest_mac = b"\xff\xff\xff\xff\xff\xff"
        dest_ip = ip  # target ip address
        # Ethernet Header
        protocol = 0x0806  # 0x0806 for ARP
        eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, protocol)
        # ARP header
        src_ip = socket.inet_aton(source_ip)
        dst_ip = socket.inet_aton(dest_ip)
        # Hardware Type - Ethernet (1),  Transport protocol - TCP (0x0800), Hardware Address Length (6B),
        # Network Address Length (4B),  ARP operation - Request (1)
        arp_hdr = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, source_mac, src_ip, dest_mac, dst_ip)
        packet = eth_hdr + arp_hdr
        raw_socket.send(packet)

    # function for showing list of known hosts in the network
    def show(self):
        if len(self.list_of_bonds) > 0:
            # length of each part in the table
            info_part = 7
            mac_part = 19
            ip_part = 17
            int_part = 8
            time_part = 6
            if self.ssh_info is not None:
                self.ssh_verification()
            print(" Info  | MAC               | IP              | Int    | Time | Verification")
            for bond in self.list_of_bonds:
                info = same_size(bond.info, info_part)
                if bond.info != "IDS" and bond.info != "Fake?":
                    bond.info = ""
                mac = same_size(bond.mac, mac_part)
                ip = same_size(bond.ip, ip_part)
                inter = same_size(bond.int, int_part)
                timer = same_size(str(int(time.perf_counter() - bond.timer)), time_part)
                if bond.info == "IDS":
                    timer = same_size(str(int(bond.timer)), time_part)
                print(info + mac + ip + inter + timer + verification_to_string(bond.verification))
            print("____________________________________________________________________________________________")

    # function for ssh verification of MAC addresses
    def ssh_verification(self):
        # mac_int = ssh_get_arp("192.168.88.1", "admin", "mikrotik")
        mac_int = ssh_get_arp(self.ssh_info[0], self.ssh_info[1], self.ssh_info[2])
        if mac_int is False:
            return False
        set_of_ints = set()
        for bond in self.list_of_bonds:
            for key in mac_int:
                set_of_ints.add(mac_int[key])
                if bond.mac == key and bond.verification < 2:
                    bond.int = mac_int[key]
                    bond.verification = 1
                    mac_int.pop(key)
                    break
                elif bond.mac == key and bond.verification > 1:
                    mac_int.pop(key)
                    break
        if len(mac_int) != 0:
            for interface in set_of_ints:
                num = 1
                mac = False
                for key in mac_int:
                    if mac_int[key] == interface:
                        num += 1
                        mac = key
                if mac is not False and num > 2:
                    self.list_of_bonds.append(Bond(mac, "-", interface, num, "Fake?"))

    # function for getting number of hosts in the network
    def get_hosts_in_network(self):
        start = time.perf_counter()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        list_info=[True,True,True]
        print("Heimdall is scanning!")
        while True:

            if self.interval_actual / 4 < time.perf_counter() - start and list_info[0]:
                print("Scanning: 25%")
                list_info[0] = False
            elif self.interval_actual / 2 < time.perf_counter() - start and list_info[1]:
                print("Scanning: 50%")
                list_info[1] = False
            elif 3 * self.interval_actual / 4 < time.perf_counter() - start and list_info[2]:
                print("Scanning: 75%")
                list_info[2] = False
            if time.perf_counter() - start > self.interval_actual:
                print("Scanning: Done!")
                break
            # catching packet
            data, addr = s.recvfrom(65535)
            # unpacking ethernet header
            ether = ethernet(data)
            if ether[2] == 1544:
                self.arp_receive(ether[1])
            self.arp_send()
        return len(self.list_of_bonds)

    def connect_mac_ip_int(self):
        a = True
        while a:
            a = self.connect_mac_ip_int_help()
        return True

    def connect_mac_ip_int_help(self):
        for i in range(0, len(self.list_of_bonds)):
            if self.list_of_bonds[i].ip == "-":
                for bond in self.list_of_bonds:
                    if self.list_of_bonds[i].mac == bond.mac and bond.ip != "-":
                        bond.int = self.list_of_bonds[i].int
                        self.list_of_bonds.pop(i)
                        return True
        return False

    # function for running ARP scan
    def run(self, ether):
        if ether[2] == 1544:
            self.arp_receive(ether[1])
        self.arp_send()
        if time.perf_counter() - self.timer_actual > 21:
            self.list_actual()
            self.show()
            self.timer_actual = time.perf_counter()


# help function for dynamically change size of part of the table
def same_size(info, size):
    string_info = " " + str(info)
    while len(string_info) < size:
        string_info += " "
    string_info += "|"
    return string_info


# function for translating verification number to word comment
def verification_to_string(value):
    if value == 0:
        return " Not Verified"
    elif value == 1:
        return " Verified"
    else:
        return " " + str(value - 1) + " MAC Addresses"


# function for getting MAC address of Local Machine
def get_my_mac():
    pseudo_mac = hex(uuid.getnode())
    help_mac = (14 - len(pseudo_mac)) * "0" + pseudo_mac[2:]
    mac = ""
    for i in range(0, len(help_mac)):
        mac += help_mac[i]
        if i % 2 == 1 and i != 11:
            mac += ":"
    return mac


# function for getting IP address of Local Machine
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.168.133.1", 1))
    ip = s.getsockname()[0]
    s.close()
    return ip
