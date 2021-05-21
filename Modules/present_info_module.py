import time


def get_detection_info(detection, boarder, max_width):
    type_det_part_width = 12
    det_info = " " + 51 * "_" + "\n"
    sentence = "DETECTION - "
    if detection is None:
        det_info += "|" + same_size(sentence + "DISABLED", max_width) + "\n"
    else:
        list_det_info = [detection.syn_on, detection.udp_on, detection.icmp_on, detection.complex_on]
        det_info += "|" + same_size(sentence + "ENABLED", max_width) + "\n"
        det_info += "|" + same_size("SYN Flood", type_det_part_width) + same_size("UDP Flood",
                                                                                  type_det_part_width) + same_size(
            "ICMP Flood", type_det_part_width) + same_size("Complex", type_det_part_width) + "<--TYPE\n"
        det_info += "|"
        for info in list_det_info:
            word = "DISABLED"
            if info:
                word = "ENABLED"
            det_info += same_size(word, type_det_part_width)
        det_info += "<--ENABLED?\n|"
        index = 0
        for info in list_det_info:
            if info:
                det_info += same_size(rule_help(detection.rule_on_one_host[index], index), type_det_part_width)
                index += 1
            else:
                det_info += same_size("-", type_det_part_width)
        det_info += "<--RULE (PER HOST)\n|"
        index = 0
        for info in list_det_info:
            if info:
                det_info += same_size(str(detection.list_of_timers[index]), type_det_part_width)
                index += 1
            else:
                det_info += same_size("-", type_det_part_width)
        det_info += "<--TIMERS\n"

    det_info += boarder
    # print(det_info)
    return det_info


def get_arp_info(scan, network, hosts, boarder, width):
    arp_info = "|"
    sentence = "ARP SCAN - "
    if scan is None:
        arp_info += same_size(sentence + "DISABLED", width) + "\n"
    else:
        arp_info += same_size(sentence + "ENABLED", width) + "\n|"
        arp_info += same_size("NETWORK: " + network, width) + "\n|"
        arp_info += same_size("NUMBER OF HOSTS: " + str(hosts), width) + "\n"
    arp_info += boarder
    # print(arp_info)
    return arp_info


def get_learn_info(learn, board, width):
    learn_info = "|"
    sentence = "LEARNING - "
    if learn is None:
        learn_info += same_size(sentence + "DISABLED", width) + "\n"
    else:
        learn_info += same_size(sentence + "DONE", width) + "\n"
    learn_info += board
    # print(learn_info)
    return learn_info


def get_ssh_info(ssh_ip, ssh_client, board, width):
    ssh_info = "|"
    sentence = "SSH - "
    if ssh_ip is None:
        ssh_info += same_size(sentence + "DISABLED", width) + "\n"
    else:
        ssh_info += same_size(sentence + "ENABLED", width) + "\n|"
        ssh_info += same_size("CLIENT: " + ssh_client, width) + "\n|"
        ssh_info += same_size("IP: " + ssh_ip, width) + "\n"
    ssh_info += board
    # print(ssh_info)
    return ssh_info


def get_safe_int_info(safe_int, board, width):
    safe_int_info = "|"
    sentence = "SAFE INTERFACES: "
    if safe_int is None or safe_int == []:
        safe_int_info += same_size(sentence + "NOT GIVEN", width) + "\n"
    else:
        safe_int_info += same_size(sentence, width) + "\n|"
        sentence = ""
        for i in range(0, len(safe_int)):
            if i == len(safe_int) - 1:
                sentence += safe_int[i]
            else:
                sentence += safe_int[i] + ", "
        safe_int_info += same_size(sentence, width) + "\n"
    safe_int_info += board
    # print(safe_int_info)
    return safe_int_info


def inform_user(detection, arp_scan, network, hosts, learn, ssh, safe_int):
    max_width = 51
    boarder = "|" + 51 * "_" + "|\n"
    ssh_ip = None
    ssh_client = None
    if ssh is not None:
        ssh_ip = ssh[0]
        ssh_client = ssh[1]
    det_info = get_detection_info(detection, boarder, max_width)
    arp_info = get_arp_info(arp_scan, network, hosts, boarder, max_width)
    learn_info_ = get_learn_info(learn, boarder, max_width)
    ssh_info = get_ssh_info(ssh_ip, ssh_client, boarder, max_width)
    safe_int_info = get_safe_int_info(safe_int, boarder, max_width)
    print(det_info + arp_info + learn_info_ + ssh_info + safe_int_info)


def rule_help(rule, is_syn):
    if is_syn == 0 and rule < 1:
        rule = str(rule)[0:5]
    else:
        rule = str(int(rule))
    max_size = 5
    len_of_rule = len(rule)
    new_rule = rule + (max_size - len_of_rule) * " "
    return new_rule


# function for logging events
def logging(parameter, mac, ip, type):
    time_now = time.ctime(time.time())
    # parameter for detection = parameter which broke rule, for scan is Interface info
    # type 0-Syn Flood, 1-Udp Flood, 2- Icmp flood, 3- Flood, 4 - New Host
    if type == 0:
        stype = "SYN Flood"
    elif type == 1:
        stype = "UDP Flood"
    elif type == 2:
        stype = "ICMP Flood"
    elif type == 3:
        stype = "Flood Attack"
    elif type == 4:
        stype = "New Host!"
    list_of_parameters = [time_now, stype, str(parameter), mac, ip]
    log = "; ".join(list_of_parameters)
    if type != 4:
        print(log)
    try:
        f = open("heimdall_logs.log", "a")
        f.write(log + "\n")
    finally:
        f.close()


# help function for dynamically change size of part of the table
def same_size(info, size):
    string_info = " " + str(info)
    while len(string_info) < size:
        string_info += " "
    string_info += "|"
    return string_info


