from Modules.packets import *
from Modules.detection_classes import *
from Modules.detection_module import *
from Modules.sniffer_tools import *
import socket
from Modules.arp_scan_module import *
from Modules.ip_network_tools import *
from Modules.parse_module import *
from Modules.learn_module import *
from Modules.present_info_module import inform_user


# need to be configured on IDS
# ip link set [interface] promisc on


def run():
    # get arguments from command line
    info = parse()
    #  [0:det_con, 1:scan, 2:learn, 3:hosts, 4:ssh, 5:safe]
    # in case wrong arguments were given
    if info is False:
        return False

    hosts = info[3]

    # ARP SCAN SET
    arp = None
    if info[1] is not None:
        #  ip_help, part = ip_control("192.168.133.0/24")
        list_of_ips = ip_address_generator(info[1][0], info[1][1])
        arp = ArpScan(list_of_ips, 10, 50, info[4])
        if info[0] is not None:
            hosts = arp.get_hosts_in_network()
    if hosts is not None and hosts > 2:
        hosts -= 2
    # LEARNING
    learning = None
    if info[2] is not None:
        info[0] = learn(info[0], info[2], hosts)
        learning = True
    # DETECTION SET
    det = None
    if info[0] is not None:
        det = Detection(info[0], info[4], info[5], hosts)

    # INFORM USER
    inform_user(det, arp, info[6], hosts, learning, info[4], info[5])

    # creating socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        # catching packet
        data, addr = s.recvfrom(65535)
        # unpacking ethernet header
        ether = ethernet(data)

        # ARP SCAN
        if info[1] is not None:
            arp.run(ether)
            # change dynamically number of host for detection
            if info[0] is not None:
                hosts = arp.get_number_of_hosts()
                if hosts > 2:
                    hosts -= 2
        # DETECTION
        if info[0] is not None:
            # detecting part
            det.run(ether, hosts)


run()
