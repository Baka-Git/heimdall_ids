from Modules.detection_classes import *
from Modules.packets import *
from Modules.ssh_module import *
from Modules.sniffer_tools import *


class Detection:
    def __init__(self, det_con, ssh_info, safe_int, number_of_hosts):
        # list of rules on one host, given by learning module, user or default
        self.rule_on_one_host = []
        self.list_of_timers=[]
        # if detection is enabled, this will enabling each detection mode by given setting
        if det_con is not None:
            self.syn_on = det_con[0][0]
            self.udp_on = det_con[1][0]
            self.icmp_on = det_con[2][0]
            self.complex_on = det_con[3][0]
            #  setting basic rules for one user
            for i in range(0, len(det_con)):
                if det_con[i][0] is True:
                    self.rule_on_one_host.append(det_con[i][2])
                    self.list_of_timers.append(det_con[i][1])
        #  if detection is not enabled, all modes are shut down
        else:
            self.syn_on = False
            self.udp_on = False
            self.icmp_on = False
            self.complex_on = False
        self.list_of_detection = []  # list witch Detection Modes
        self.list_of_packets = Packets()  # list with caught Packets
        self.ssh_info = ssh_info  # info for SSH connection for Banning the "Bad Guy"
        self.safe_int = safe_int  # list of interfaces which cannot be Ban or ar known that will not be corrupted
        self.number_of_hosts = number_of_hosts  # number of hosts in the network
        # change rules according number of host, syn rule will not be change, because syn rule is not depending on
        # number of hosts
        for i in range(1, len(det_con)):
            det_con[i][2] = det_con[i][2] * self.number_of_hosts * 2
        # setting all rules for each mode if it is enabled
        if self.syn_on:
            self.list_of_detection.append(SynFlood(det_con[0][1], det_con[0][2]))
        if self.udp_on:
            self.list_of_detection.append(UdpFlood(det_con[1][1], det_con[1][2]))
        if self.icmp_on:
            self.list_of_detection.append(IcmpFlood(det_con[2][1], det_con[2][2]))
        if self.complex_on:
            self.list_of_detection.append(ComplexDetection(det_con[3][1], det_con[3][2], 40))

    # function for giving Detection modes information about communication
    def actual(self, info, number_of_hosts):
        for i in range(0, len(self.list_of_detection)):
            #   if number of hosts in the network changes, rules will be changed dynamically according this number
            if number_of_hosts != self.number_of_hosts:
                self.list_of_detection[i].change_rule(number_of_hosts * self.rule_on_one_host[i])
            self.list_of_detection[i].actual(info)

    #  function for using every enabled Detection mode
    def detection(self):
        for det_class in self.list_of_detection:
            det_value = det_class.detection()
            if det_value is not False:
                # print(det_class.id)
                self.log(det_class.id, det_value)

    def log(self, type, parameter):
        mac, ip = self.attacker_hunter(type)
        # if SSH Module is enabled, interface where BAD MAC address is found will be shutdown
        if self.ssh_info is not None:
            ssh_ban(self.safe_int, mac, self.ssh_info[0], self.ssh_info[1], self.ssh_info[2])
        time_now = time.ctime(time.time())
        if type == 0:
            stype = "SYN Flood"
        elif type == 1:
            stype = "UDP Flood"
        elif type == 2:
            stype = "ICMP Flood"
        else:
            stype = "Flood Attack"
        list_of_parameters = [time_now, stype, str(parameter), mac, ip]
        log = "; ".join(list_of_parameters)
        print(log)
        try:
            f = open("heimdall_logs.log", "a")
            f.write(log + "\n")
        finally:
            f.close()

    def attacker_hunter(self, type):
        # list of all source MAC addresses in list of all packets
        list_of_mac = []
        # set of all IP addresses in list of all source IP
        list_of_original_mac = set()

        # finding most used MAC address
        # creating set and list of all source IP addresses
        if type == 3:
            for packet in self.list_of_packets.packets:
                list_of_mac.append(packet.mac)
                list_of_original_mac.add(packet.mac)
        elif type == 0:
            for packet in self.list_of_packets.packets:
                if packet.type == type and packet.flag == 0:
                    list_of_mac.append(packet.mac)
                    list_of_original_mac.add(packet.mac)
        else:
            for packet in self.list_of_packets.packets:
                if packet.type == type:
                    list_of_mac.append(packet.mac)
                    list_of_original_mac.add(packet.mac)
        max = 0
        max_mac = ""
        # searching for most used MAC addresses
        for mac in list_of_original_mac:
            count = list_of_mac.count(mac)
            if count > max:
                max = count
                max_mac = mac
            # searching for last used IP address of this MAC
        ip = ""
        for packet in self.list_of_packets.packets:

            if packet.mac == max_mac:
                ip = packet.src

        return max_mac, ip

    def run(self, ether, number_of_hosts):
        self.detection()
        # if IP protocol is used, control
        if ether[2] == 8:
            # unpacking ipv4 header
            ipv4_info = ipv4(ether[1])
            # getting type of transport protocol
            flag = 2
            #  if tcp, control syn, ack and rst
            if ipv4_info[0] == 6:
                tcp_info = tcp(ipv4_info[2])
                type = 0
                # syn 0, rst 0, ack 1
                if (tcp_info[0] == 1) and (tcp_info[2] == 0) and (tcp_info[1] == 0):
                    flag = 1
                    self.actual(1, number_of_hosts)
                # syn 1, ack 0
                elif (tcp_info[0] == 0) and (tcp_info[2] == 1):
                    flag = 0
                    self.actual(0, number_of_hosts)

            elif ipv4_info[0] == 17:
                self.actual(2, number_of_hosts)
                type = 1
            elif ipv4_info[0] == 1:
                self.actual(3, number_of_hosts)
                type = 2
            else:
                self.actual(4, number_of_hosts)
                type = 3
            # setting flags for SYN flood detection: 0-only syn,1-only ack,2-other
            # adding packet to the list of packets
            p = Packet(type, ether[0], ipv4_info[1], flag)
            self.list_of_packets.add_packet(p)
        return True
