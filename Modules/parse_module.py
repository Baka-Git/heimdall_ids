from Modules.ip_network_tools import *
import argparse
from Modules.ssh_module import *


def parse():
    print(
        "___    ____    ___\n\@@\   |@@|   /@@/    @@   @@   @@@@@@   @@  @@@      @@@    @@@@@       @@@@     @@     "
        "@@\n \@@\  |@@|  /@@/    @@   @@   @@       @@  @@\@@   @@/@@    @@   @@    @@ @@    @@     @@\n  \@@\ |@@| "
        "/@@/   @@@@@@@@   @@@@@@   @@  @@   @@@@  @@   @@    @@   @@   @@   @@     @@\n   \@@\|@@|/@@/   @@    @@   @@ "
        "      @@  @@    @@   @@   @@    @@   @@@@@@@@  @@     @@ \n    \@@@@@@@@/   @@    @@   @@@@@@@  @@  @@         "
        "@@  @@@@@@@    @@      @@ @@@@@@ @@@@@@@\n     \@@@@@@/\n      \@@@@/    @@  @@@   @@@@       Vyrobil (Made "
        "by): Baka\n       |@@|    @@  @@ @@ @@          V rámci Bakalářské práce (For Bachelor Thesis)\n       "
        "|@@|   @@  @@ @@   @@\n       |@@|  @@  @@@@  @@@@ \n       |@@|\n       |@@|")
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--detection",
                        help="Enables Detection Module. Detection to enable: syn - Syn Flood detection, udp - UDP "
                             "Flood detection, icmp - ICMP Flood detection, complex - Complex detection. Example '-d "
                             "syn', '-d syn,udp' In case of enabling all detetion modes use: '-d all'")
    parser.add_argument("-t", "--detection_timer", help="Enables to change timer of one round for specific type of "
                                                        "detection. Format is DETECTION-TIMER. Examples: '-t syn-60', "
                                                        "'syn-60,udp-5'")
    parser.add_argument("-r", "--detection_rule", help="Enables to change parameter of rule for Detection Module. "
                                                       "Format is DETECTION-PARAMETER. Example '-r syn-1.5', 'syn-1.5,"
                                                       "udp-2'")
    parser.add_argument("-n", "--number_of_hosts",
                        help="Setting static number of hosts in the network. It is necessary "
                             "argument, if learning module is not enabled. Example: '-n 5'")
    parser.add_argument("-s", "--scan", help="Enables Scanning Module. Argument to enable scan are network + mask. "
                                             "Example: '-s 192.168.1.0/24'")
    parser.add_argument("-l", "--learn", help="Enables Learning Module. It can be used only if Detection Module is "
                                              "enabled. Argument to enable module is number of seconds for learning "
                                              "part. "
                                              "Example: '-l 60'")
    parser.add_argument("-c", "--connect_ssh",
                        help="Enables SSH Module. IDS will connect to by SSH to Mikrotik router with "
                             "given credentials (IP address of router, username). User will be asked "
                             "for password in the process. Example:'-c 192.168.88.1,admin'")
    parser.add_argument("-i", "--safe_interface", help="To set safe interfaces on the Router. IDS cannot shutdown this "
                                                       "interfaces. This argument must be used together with SSH. "
                                                       "Example: '-i ether0,ether1'")
    args = parser.parse_args()
    # print(args)
    values = arg_control(args)
    return values


def int_control(maybe_int):
    try:
        a = int(maybe_int)
    except:
        return False
    return a


def ssh_arg(args):
    list_help = args.split(",")

    if len(list_help) != 2:
        return False
    password = input("Enter your password for Mikrotik router: ")
    value = ssh_command_execute("interface bridge host print", list_help[0], list_help[1], password)
    if value == False:
        print("SSH connection failed. IP, username or password is wrong!")
        return False
    return [list_help[0], list_help[1], password]


def det_arg_con(list_of_det, list_of_timer, list_of_rule):
    if list_of_det is None:
        list_of_det = [False, False, False, False]
    if list_of_timer is None:
        list_of_timer = [5, 5, 5, 1]
    if list_of_rule is None:
        list_of_rule = [1 / 2, 20, 20, 20]
    list_con = [[False, 0, 0], [False, 0, 0], [False, 0, 0], [False, 0, 0]]
    for i in range(0, 4):
        if list_of_det[i] != 0:
            list_con[i][0] = True
            list_con[i][1] = list_of_timer[i]
            list_con[i][2] = list_of_rule[i]

    return list_con


def det_arg(args, basic):
    if args == "all":
        return [True, True, True, True]
    list_help = args.split(",")
    list_of_det_info = [0, 0, 0, 0]
    for arg in list_help:
        if basic != True:
            help = arg.split("-")
            help[0].lower()
            try:
                help[1] = float(help[1])
            except:
                "Wrong format of parameter"
                return False
        else:
            help = [arg.lower(), True]
        if help[0] == "syn":
            list_of_det_info[0] = help[1]
        elif help[0] == "udp":
            list_of_det_info[1] = help[1]
        elif help[0] == "icmp":
            list_of_det_info[2] = help[1]
        elif help[0] == "complex":
            list_of_det_info[3] = help[1]

    return list_of_det_info


def control(args, type, error_message):
    if args is not None:
        if type == 0:  # det_info
            args = det_arg(args, True)
        elif type == 1:  # det_timer or det_rule
            args = det_arg(args, False)
        elif type == 2:  # learn or hosts
            args = int_control(args)
        elif type == 3:  # scan
            args = ip_control(args)
        elif type == 4:  # ssh
            args = ssh_arg(args)
        if args is False:
            print(error_message)
    return args


def arg_control(args):
    det_info = control(args.detection, 0, "Detection has got wrong arguments!")
    if det_info is False:
        return False
    det_rule = control(args.detection_rule, 1, "Detection timer has got wrong arguments!")
    if det_rule is False:
        return False
    det_timer = control(args.detection_timer, 1, "Detection rule parameter has got wrong arguments!")
    if det_timer is False:
        return False
    hosts = control(args.number_of_hosts, 2, "Number of hosts has got wrong argument!")
    if hosts is False:
        return False
    learn = control(args.learn, 2, "Learning has got wrong argument!")
    if learn is False:
        return False
    scan = control(args.scan, 3, "Scan has got wrong argument!")
    if scan is False:
        return False
    ssh = control(args.connect_ssh, 4, "SSH has got wrong arguments!")
    if ssh is False:
        return False
    safe = args.safe_interface
    if safe is not None:
        safe = safe.split(",")

    if ssh is not None and det_info is None and scan is None:
        print("SSH Module can be enabled only with Detection Module or ARP Scan!")
        return False
    elif learn is not None and det_info is None:
        print("Learning Module can be enabled only with Detection Module!")
        return False
    elif ssh is not None and det_info is not None and safe is None:
        print("Safe interface arguments are required if SSH Module is used!")
        return False
    elif det_timer is not None and det_info is None:
        print("Timer cannot be changed if detection is not enabled!")
        return False
    elif det_rule is not None and det_info is None:
        print("Rule parameter cannot be changed if detection is not enabled!")
        return False
    elif det_info is not None and scan is None and hosts is None:
        print("If Detection is enabled, Scan has to be enabled too, or Number of hosts must be specified!")
        return False
    det_con = det_arg_con(det_info, det_timer, det_rule)

    if det_con == [[False, 0, 0], [False, 0, 0], [False, 0, 0], [False, 0, 0]]:
        det_con = None

    if [[[False, 0, 0], [False, 0, 0], [False, 0, 0], [False, 0, 0]], None, None, None, None, None, None] == [det_con,
                                                                                                              scan,
                                                                                                              learn,
                                                                                                              hosts,
                                                                                                              ssh, safe,
                                                                                                              args.scan]:
        return False
    return [det_con, scan, learn, hosts, ssh, safe, args.scan]


