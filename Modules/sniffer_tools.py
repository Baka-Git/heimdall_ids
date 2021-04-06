import struct
import socket


# function for extracting data from ethernet message
def ethernet(data):
    # getting source MAC address
    src_mac, proto = struct.unpack('! 6s H', data[6:14])
    src = get_mac_address(src_mac)
    protocol = socket.htons(proto)
    ip_data = data[14:]
    return src, ip_data, protocol


# function for getting normal format of MAC address
def get_mac_address(adr):
    bytes = map('{:02x}'.format, adr)
    return ":".join(bytes).upper()


# function for getting normal format of IPv4 address
def get_ip_address(addr):
    return '.'.join(map(str, addr))


#  function for extracting data from IPv4 message
def ipv4(data):
    # getting first byte of IP header
    version_and_length = data[0]
    # getting length from first byte of IP header, & 15 filters length from version, *4 is that one unit int length is
    # 4 bytes
    header_length = (version_and_length & 15) * 4
    # getting information of transport protocol and source address, 9x is first 9 bytes out, that means Version[
    # 0.5], Length[0.5], Type of Service[1B], Total Length[2], Identification[2B], IP flags[0,5B], Fragment Offset[1,
    # 5B] and TTL[1B], B means 1 byte will go to protocol, 2x 2 out for Checksum[2B], 4s s is for char and 4 bytes
    # for source IP address
    protocol, src = struct.unpack('! 9x B 2x 4s', data[:16])
    # getting transport data
    transport_data = data[header_length:]
    # getting normal format of MAC address
    src = get_ip_address(src)
    return protocol, src, transport_data


###########
# function for extracting data from TCP message
def tcp(data):
    # getting
    flags = struct.unpack('! H', data[12:14])[0]
    # getting flags for detection
    ack = (flags & 16) >> 4
    rst = (flags & 4) >> 2
    syn = (flags & 2) >> 1
    return ack, rst, syn
