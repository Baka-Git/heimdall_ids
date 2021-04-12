# Heimdall IDS
Heimdall IDS is IDS for Detection and Mitigation of flood DDoS attacks in LANs.

Heimadall IDS is using paramiko library (https://github.com/paramiko/paramiko). Licence for this library can be found in folder licences. Import of paramiko can be done from CLI by command: ```pip install paramiko```. In case of trouble with pip, actualize him by command ```sudo apt install python3-pip``` and repeat previous command.

Program is created for my Bachelor Degree Work and his purpose is to detect and mitigate Flooding Attacks
## Function of Heimdall IDS:
- Detection of flood attacks (4 methods)
- ARP Scan
- Enable Learning Phase
- SSH connection to Mikrotik Router

## Use
Program should be run from terminal by command: sudo python3 main.py ARGUMENTS

## Detection
-function for enabling detection of Flood DDoS attack. If attack happends, log will be shown in console and also will be saved into the file detection.log

### Methods
-Heimdall uses 4 methods for detection:
#### 1. SYN Flood Method
 - Decidion if attack happend or not depends on ration between number of SYN packets and ACK packets.
 - In normal comunication SYN packets are used only at begining of comunication in 3-way handshake. ACK packets are used in 3-way handshake too, but are als used for conrfirmation of every packet.
 - If number of SYN packets is bigger than ACK packets chance that attack is hapenning encreases.
 - Rule is than 1-NUMBER_OF_ACK/NUMBER_OF_SYN
#### 2. UDP Flood Method
- In this method decidion depends on number of UDP datagrams.
- If number is bigger than given rule, Heimdall will signal an alarm.
- Rule is MAX_NUMER_OF_UDP.
#### 3. ICMP Flood Method
 - In this method decidion depends on number of ICMP packets.
- If number is bigger than given rule, Heimdall will signal an alarm.
 - Rule is MAX_NUMER_OF_UDP.
#### 4. Complex Method
 - Compex Method watchs traffic and compute how many packets are send for given timer.
 - Bigger number of packet than normal value does not mean attack.
 - Attack is detected if this case happend in 20times in 40times interval.
- Rule is MAX_NUMER_OF_PACKETS_FOR_TIMER.

### Logs
- information about attacks are stored in log file and shown in console line

- Structure of log:
1. part of log is time, when attack was detected
2. part is a description what attack did happen
3. part is value of parameter which was the reason why IDS marked the traffic as an attack,
4. part is an IP address of the "attack"
5. part is a MAC of the "attacker".
- Attacker is here most used MAC address and IP address which are matched togehter.
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
- to change timer for how often detection is happening [seconds]
```# change one timer for method
-t syn-5
# change several timers for methods
-t syn-5,udp-11
```
#### Rules
- to change rules for methods [packets/host]
```
# change rule for one mehtod
-r syn-2
# change rules for several methods
-r syn-2,compex-100
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
- Module for findig all hosts in the network
- Use ARP request to findout if IP address is UP or DOWN
- If known IP address does not respond in given time, host will be set in IDS as DOWN
- In use with Detection Module, rules can be dynamicaly changed depedniding how many host are in the network
- Scan can be use also without other Modules
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
- Module for comunication with Mikrotik Router
- paramiko library is used in this Module
- Module enables shuting down ports where attacker is, and enable to connect host to the interface on the Router
- Required parameter to enable SSH module is set some interfaces as SAFE (Interfaces cannot be shut down)
- Module can be used only if Detection Module or ARP Scan is used too
```
# format is -c IP,USERNAME -i INTERFACE1,INTERFACE2,...
sudo python3 main.py -d all -l 120 -c 192.168.1.1,admin -i ether0
```