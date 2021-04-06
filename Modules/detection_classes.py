import time


class SynFlood:
    def __init__(self, timer, limit):
        self.syn = 0
        self.ack = 0
        self.limit = limit
        self.interval_of_detection = timer
        self.timer_of_detection = time.perf_counter()
        self.min = 5
        self.id = 0

    def change_rule(self, new_rule):
        return True

    def actual(self, info):
        if info == 0:
            self.syn += 1
        if info == 1:
            self.ack += 1

    def detection(self):
        if time.perf_counter() - self.timer_of_detection > self.interval_of_detection:
            if self.syn > self.min and 1 - self.ack / self.syn > self.limit:
                parameter = 1 - self.ack / self.syn
                self.timer_of_detection = time.perf_counter()
                self.ack = 0
                self.syn = 0
                return parameter
            self.ack = 0
            self.syn = 0
        return False


class UdpFlood:
    def __init__(self, timer, maximum):
        self.udp = 0
        self.interval_of_detection = timer
        self.timer_of_detection = time.perf_counter()
        self.maximum = maximum
        self.id = 1

    def change_rule(self, new_rule):
        self.maximum = new_rule
        return True

    def actual(self, info):
        if info == 2:
            self.udp += 1
        return True

    def detection(self):
        if time.perf_counter() - self.timer_of_detection > self.interval_of_detection:
            self.timer_of_detection = time.perf_counter()
            if self.udp > self.maximum:
                parameter = self.udp
                self.udp = 0
                return parameter
            self.udp = 0
        return False


class IcmpFlood:
    def __init__(self, timer, maximum):
        self.icmp = 0
        self.interval_of_detection = timer
        self.timer_of_detection = time.perf_counter()
        self.timer_of_reset = time.perf_counter()
        self.maximum = maximum
        self.id = 2

    def change_rule(self, new_rule):
        self.maximum = new_rule
        return True

    def actual(self, info):
        if info == 3:
            self.icmp += 1

    def detection(self):
        if time.perf_counter() - self.timer_of_detection > self.interval_of_detection:
            self.timer_of_detection = time.perf_counter()
            if self.icmp > self.maximum:
                parameter = self.icmp
                self.icmp = 0
                return parameter
            self.icmp = 0
        return False


class ComplexDetection:
    def __init__(self, timer, number_of_danger, ranger):
        self.list = []
        self.ranger = ranger
        self.number_of_danger = number_of_danger
        self.interval_of_detection = timer
        self.timer_of_value = time.perf_counter()
        self.timer_of_detection = time.perf_counter()
        self.number = 0
        self.id = 3

    # function for move list for one place
    def move(self):
        new_list = self.list.copy()
        for i in range(self.ranger - 1):
            self.list[i] = new_list[i + 1]

    # function for adding new number to the list
    def add_number(self, number):
        if len(self.list) < self.ranger:
            self.list.append(number)
        else:
            self.move()
            self.list[self.ranger - 1] = number

    def change_rule(self, new_rule):
        self.number_of_danger = new_rule
        return True

    def actual(self, info):
        self.number += 1
        if time.perf_counter() - self.timer_of_value > 3:
            self.add_number(self.number)
            self.number = 0
            self.timer_of_value = time.perf_counter()

    def detection(self):
        if time.perf_counter() - self.timer_of_detection > self.interval_of_detection:
            self.timer_of_detection = time.perf_counter()
            danger = 0
            for number in self.list:
                if number > self.number_of_danger:
                    danger += 1
            if danger > self.ranger / 2:
                return danger
        return False
