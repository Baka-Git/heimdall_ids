# Heimdall IDS
Heimdall IDS is IDS for Detection and Mitigation of flood DDoS attacks in LANs.

Heimadall IDS is using paramiko library (https://github.com/paramiko/paramiko). Licence for this library can be found in folder licences. Import of paramiko can be done from CLI by command: ```pip install paramiko```. In case of trouble with pip, actualize him by command ```sudo apt install python3-pip``` and repeat previous command.

Program is created for my Bachelor Degree Work and his purpose is to detect and mitigate Flooding Attacks
## Function of Heimdall IDS:
- Detection of flood attacks (4 methods)
- ARP Scan
- Enable Learning Phase
- SSH connection to Mikrotik Router

## Use and Requirements
Router should mirror all traffic to interface where IDS is.
Example for Mikrotik:
```
/interface ethernet switch
set switch1 mirror-source=none mirror-target=ether3
/interface ethernet switch rule
add mirror=yes ports=ether1,ether2 switch=switch1
```
Machine with IDS should also have interface set in promiscuous mode. Example for Linux:
```
ip link set ether1 mode promisc on
```
Program should be run from terminal by command: 
```
sudo python3 main.py ARGUMENTS
```

## Detection Module
- Module for enabling detection of Flood DDoS attack. If attack happends, log will be shown in console and also will be saved into the file heimdall_logs.log

### Methods
- Heimdall uses 4 methods for detection:
#### 1. SYN Flood Method
 - Decision if attack happened or not depends on ration between number of SYN packets and ACK packets.
 - In normal communication SYN packets are used only at beginning of communication in 3-way handshake. ACK packets are used in 3-way handshake too, but are als used for conrfirmation of every packet.
 - If number of SYN packets is bigger than ACK packets chance that attack is happening increases.
 - Rule is than 1-NUMBER_OF_ACK/NUMBER_OF_SYN
#### 2. UDP Flood Method
- In this method decision depends on number of UDP datagrams.
- If number is bigger than given rule, Heimdall will signal an alarm.
- Rule is MAX_NUMBER_OF_UDP.
#### 3. ICMP Flood Method
 - In this method decision depends on number of ICMP packets.
- If number is bigger than given rule, Heimdall will signal an alarm.
 - Rule is MAX_NUMBER_OF_UDP.
#### 4. Complex Method
 - Complex Method watches traffic and compute how many packets are send for given timer.
 - Bigger number of packet than normal value does not mean attack.
 - Attack is detected if this case happened in 20times in 40times interval.
- Rule is MAX_NUMBER_OF_PACKETS_FOR_TIMER.

### Detection Logs
- Information about attacks are stored in log file and shown in console line

- Structure of log:
1. Part of log is time, when attack was detected
2. Part is a description what attack did happen
3. Part is value of parameter which was the reason why IDS marked the traffic as an attack
4. Part is an IP address of the "attack"
5. Part is a MAC of the "attacker"
- Attacker is here most used MAC address and IP address which are matched togehter
- Example of log:
```
Mon Mar 22 14:57:38 2021; UDP Flood; 9; 00:50:56:C0:00:08; 192.168.133.1
```
### Settings

#### Enabling methods
```
# Enable SYN Method
-d syn
# Enable UDP Method
-d udp
# Enable ICMP Method
-d icmp
# Enable Complex Method
-d complex
# Enable several Methods
-d syn,udp,icmp
# Enable all Methods
-d all
```
#### Timers
- Parameter to change timer for how often detection is happening [seconds]
```# change one timer for method
-t syn-5
# change several timers for methods
-t syn-5,udp-11
```
#### Rules
- Parameter to change rules for methods [packets/host]
```
# change rule for one method
-r syn-2
# change rules for several methods
-r syn-2,complex-100
```
### Minimum parameters to enable Detection Module
- Detection Module can be enabled only if number of host is known
- That could be done by manual set number of hosts or enable ARP Scan
### Examples of enabling Detection Module
```
# first example
sudo main.py -d all -r syn-0.3,udp-100 -t complex-5 --number_of_hosts 5
#second  example
sudo python3 main.py -d syn,udp -s 192.168.1.0/24 
```
## ARP Scan
- Module for finding all hosts in the network
- Use ARP request to find out if IP address is UP or DOWN
- If known IP address does not respond in given time, host will be set in IDS as DOWN
- In use with Detection Module, rules can be dynamically changed depending how many host are in the network
- Scan can be use also without other Modules
- New found hosts are logged into log file, in CLI are information presented not in log format but in overview table
### Scan Log
- Information about NEW hosts in the network
- In case known host will be for some time inactive, he will be logged as new host, when he return
- Structure of log:
1. Part of log is time, when attack was detected
2. Part is a information that log is about New Host
3. Part is interface on Mikrotik if it is known (if it is not known value will be "-")
4. Part is an IP address of the new host
5. Part is a MAC of the new host
- Example of log:
```
Mon Mar 22 14:57:38 2021; New Host; ether3; 00:50:56:C0:00:08; 192.168.133.135
```
### Enable ARP Scan
```
#format -s NETWORK/MASK
# in solo mode
sudo python3 main.py -s 192.168.133.0/24
# together with Detection Module
sudo python3 main.py -d syn,udp -s 192.168.1.0/24
```
## Learning Module
- Module to help setting rules for Detection Module
- Module listen to the traffic and depending how much is which protocol used are rule set
- This module can be ONLY used only if Detection Module is in use too
### Enable Learning Module
```
# format is -l TIME_FOR_LEARNING_IN SECONDS
sudo python3 main.py -d all -l 120
```
## SSH Module
- Module for communication with Mikrotik Router
- paramiko library is used in this Module
- Module enables shutting down ports where attacker is, and enable to connect host to the interface on the Router
- Required parameter to enable SSH module is set some interfaces as SAFE (Interfaces cannot be shut down)
- Module can be used only if Detection Module or ARP Scan is used too
```
# format is -c IP,USERNAME -i SAFE_INTERFACE1,SAFE_INTERFACE2,...
sudo python3 main.py -d all -l 120 -c 192.168.1.1,admin -i ether0
```