def ip_ref(address, part, list):
    help = address
    for n in range(0, 256):
        if part == 1 or part == 2:
            address = address + str(n) + "."
            ip_ref(address, part + 1, list)
        elif n != 0 or n != 255:
            address = address + str(n)
            list.append(address)
        address = help


# function for generating list of IP addresses in the Network
def ip_address_generator(list, part):
    a = ""
    # run through part of address in which does not change
    for num in range(0, part):
        a = a + str(list[num]) + "."
    # run through part of address which changes
    mask = list[4]
    if part == 1:
        mask -= 8
    elif part == 2:
        mask -= 16
    elif part == 3:
        mask -= 24
    list_of_ips = []
    ranger = mask_control(list[part], mask)
    help_value = a
    for n in range(list[part], list[part] + ranger):
        help_value += str(n)
        if part != 3:
            help_value += "."
            ip_ref(help_value, part + 1, list_of_ips)
        elif part == 3:
            list_of_ips.append(help_value)
        help_value = a
    list_of_ips.pop()
    list_of_ips.pop(0)
    return list_of_ips


# help function for control mask of the network
def mask_control(part, mask):
    if mask == 0 and part == 0:
        return 256
    elif mask == 1 and part % 128 == 0:
        return 128
    elif mask == 2 and part % 64 == 0:
        return 64
    elif mask == 3 and part % 32 == 0:
        return 32
    elif mask == 4 and part % 16 == 0:
        return 16
    elif mask == 5 and part % 8 == 0:
        return 8
    elif mask == 6 and part % 4 == 0:
        return 4
    elif mask == 7 and part % 2 == 0:
        return 2
    return False


# function for controlling Format of IP addresses
def ip_control(ip):
    list = []
    a = ""
    i = 0
    lengh = len(ip)
    # split IP address to parts
    for ch in ip:
        i += 1
        # print(ch+" "+str(i))
        if ch == "." or ch == "/":
            list.append(a)
            a = ""
        elif i == lengh:
            a += ch
            list.append(a)
        else:
            a += ch
    if len(list) != 5:
        return False
    # control if part of network address is int and has suitable size
    i = 0
    for num in list:
        i += 1
        try:
            num = int(num)
        except:
            return False
        if not ((num < 255 and i != 5) or (num <= 30 and i == 5)):
            return False
        list[i - 1] = int(list[i - 1])
    # control mask part 1
    mask = list[4]
    part = 0
    if 8 <= mask < 16:
        part = 1
        mask -= 8
    elif 16 <= mask < 24:
        part = 2
        mask -= 16
    elif mask >= 24:
        part = 3
        mask -= 24
    if not mask_control(list[part], mask):
        return False
    # control mask and network address part 2
    for n in range(part + 1, 4):
        if list[n] != 0:
            return False

    return list, part
