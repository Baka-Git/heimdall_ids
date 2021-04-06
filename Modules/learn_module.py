import socket
from Modules.sniffer_tools import *
import time


def learn(det_con, time_for_learn, hosts):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #  [syn_counter, ack_counter, udp_counter, icmp_counter, complex_counter]
    list_of_counter = [0, 0, 0, 0, 0]  # counter of protocols

    # list of enabled Detection Mods [syn_on, syn_on, udp_on, icmp_on, complex_on]
    list_of_det = [det_con[0][0], det_con[0][0], det_con[1][0], det_con[2][0], det_con[3][0]]

    # list of timers for each Detection Mod [time_det_syn, time_det_syn, time_det_udp, time_det_icmp, time_det_complex]
    list_of_times = [det_con[0][1], det_con[0][1], det_con[1][1], det_con[2][1], det_con[3][1]]

    time_help = time.perf_counter()  # help timer

    # timers for each Detection Mod  [timer_for_syn, timer_for_ack, timer_for_udp, timer_for_icmp, timer_for_complex]
    list_of_timers = [time_help, time_help, time_help, time_help, time_help]

    list_of_temp_values = [0, 0, 0, 0, 0]
    start = time.perf_counter()
    list_info = [0, 0, 0]
    print("Heimdall is learning!")
    while True:
        # catching packet
        data, addr = s.recvfrom(65535)
        # unpacking ethernet header
        ether = ethernet(data)

        if ether[2] == 8:
            # unpacking ipv4 header
            ipv4_info = ipv4(ether[1])
            # getting type of transport protocol
            # tcp
            if list_of_det[0] and (ipv4_info[0] == 6):
                tcp_info = tcp(ipv4_info[2])
                # ack
                if (tcp_info[0] == 1) and (tcp_info[2] == 0) and (tcp_info[1] == 0):
                    list_of_temp_values[1] += 1
                # syn
                elif (tcp_info[0] == 0) and (tcp_info[2] == 1):
                    list_of_temp_values[0] += 1
            # udp
            elif list_of_det[1] and (ipv4_info[0] == 17):
                list_of_temp_values[2] += 1
            # icmp
            elif list_of_det[2] and (ipv4_info[0] == 1):
                list_of_temp_values[3] += 1
            if list_of_det[3]:
                list_of_temp_values[4] += 1

        for point in range(0, 5):
            # if Detection Mode is on and time for its detection is up, check counter, and if is his max value,
            # set it as max value
            if list_of_det[point] and (time.perf_counter() - list_of_timers[point] > list_of_times[point]):
                list_of_timers[point] = time.perf_counter()
                if list_of_temp_values[point] > list_of_counter[point]:
                    # if point==2:
                    #   print(time.ctime(time.time()))
                    #  print(list_of_temp_values[point])
                    list_of_counter[point] = list_of_temp_values[point]
                list_of_temp_values[point] = 0

        if time_for_learn / 4 < time.perf_counter() - start and list_info[0] == 0:
            print("Learning: 25%")
            list_info[0] = 1
        elif time_for_learn / 2 < time.perf_counter() - start and list_info[1] == 0:
            print("Learning: 50%")
            list_info[1] = 1
        elif 3 * time_for_learn / 4 < time.perf_counter() - start and list_info[2] == 0:
            print("Learning: 75%")
            list_info[2] = 1

        if time.perf_counter() - start > time_for_learn:
            print("Learning: Done!")
            break

    list_of_rule = [0.5, 0, 0, 0]
    for i in range(0, 5):
        list_of_counter[i] = list_of_counter[i] / hosts

    # return value of counter of packets of each type for ONE host in given timer

    for i in range(0, 4):
        if i == 0:
            if list_of_counter[0] == 0:
                det_con[i][2] = 0.5
            else:
                det_con[i][2] = 1 - list_of_counter[1] / list_of_counter[0]
        else:
            det_con[i][2] = list_of_counter[i + 1]

    return det_con

# learn(True, True, True, True, 10, 10, 10, 3, 120, 2)
