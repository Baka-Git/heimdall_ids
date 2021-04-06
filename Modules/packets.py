class Packet:
    def __init__(self, type, mac, src, flag):
        # type of Transport protocol: 0-TCP,1-UDP,2-ICMP,3-Other
        self.type = type
        # MAC address of source PC
        self.mac = mac
        # Source IP address
        self.src = src
        # Flags in TCP header: 0-Only SYN, 1-Only ACK, 2-other
        self.flag = flag

    # print info about packet
    def packet_print(self):
        print("Type: " + str(self.type) + "\n"
              + "Source IP address: " + self.src + "\n"
              + "Source Mac Addres: " + str(self.mac) + "\n"
              + "Flags: " + str(self.flag) + "\n")


##############################################################
class Packets:
    def __init__(self):
        # list of all packets
        self.packets = []

    # add new packets
    def add_packet(self, packet):
        self.packets.append(packet)

    # print last packets
    def print_last(self):
        for packet in self.packets:
            packet.packet_print()

    # restart list of lastpacket
    def refresh(self):
        self.packets = []
