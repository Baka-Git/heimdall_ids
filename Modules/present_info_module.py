from Modules.arp_scan_module import same_size


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
                det_info += same_size(str(detection.rule_on_one_host[index])[0:4], type_det_part_width)
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

# max_width = 51
# boarder = "|" + 51 * "_" + "|\n"
# a = Detection([[True, 5, 0], [False, 0, 0], [False, 0, 0], [False, 0, 5]], None, None, 3)
# det = get_detection_info(a, boarder, max_width)
# b = ArpScan([], 5, 5, None)
# arp = get_arp_info(b, "192.168.1.0/24", 5, boarder, max_width)
# learn_ = get_learn_info(True, boarder, max_width)
# ssh = get_ssh_info("192.168.1.1", "admin", boarder, max_width)
# safe_int = get_safe_int_info(["ehter1", "ether2"], boarder, max_width)
# print(det + arp + learn_ + ssh + safe_int)
# inform_user(a,None,None,None,True,None,None,[])
# help_syn_rule(0.5555555)
