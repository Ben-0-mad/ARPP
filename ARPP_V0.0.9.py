from scapy.all import *
import argparse
from time import sleep

"""
ARP poisoning is the act of altering the ARP table of another device on the network (for malicious purposes)

Steps to achieve ARP poisoning:
1. Choose victim machine on the same network
2. Get IP address of victim
3. Continuously send ARP packets (with arbitrary MAC-adress) using scapy to victim machine
4. Choosing the MAC-adress of the router will force the traffic, which usually goes from victim -> router, to flow from victim -> this machine

"""
# command line tool parser
parser = argparse.ArgumentParser(description="This program is an ARP poisoning tool")
args = parser.parse_args()


def print_banner():
    """
    Print some ASCII art for aesthetic purposes
    """
    banner="""
    _   ___ ___ ___ 
   /_\ | _ \ _ \ _ \\
  / _ \|   /  _/  _/
 /_/ \_\_|_\_| |_|  
                  By group 20
    """
    print(banner)

def print_menu():
    task_names = ["Help",\
        "Scan local network for users",\
        "ARP poison",\
        "exit"]
    
    for i, task_name in enumerate(task_names, start=0):
        print(f"{i}: {task_name}")






#### Global variables ####
my_ip : str = get_if_addr(conf.iface)
##########################

def get_ip_range(ip_range=None):
    if ip_range is None:
        ip_range = my_ip+"/24"
    return ip_range

def get_network_users_ARPSCAN():
    """
    ARP ping scan
    """
    ip_range = get_ip_range()
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
    print("Scanning devices connected to network, please wait...")
    network_devices = srp(request, timeout=10, verbose=0)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
    for i, user in enumerate(network_devices, start=1):
        #print(f"{i}: {user}\n")
        print(f"{user[1].psrc}          {user[1].hwsrc}")
    if network_devices is []:
        print("No network devices found\n")
        
def ARP_poison(machine1_ip=None, machine2_ip=None, machine1_mac=None, machine2_mac=None):
    if machine1_ip is None:
        machine1_ip = input("machine1_ip >>")
    if machine2_ip is None:
        machine2_ip = input("machine2_ip >>")
    if machine1_mac is None:
        machine1_mac = input("machine1_mac >>")
    if machine2_mac is None:
        machine2_mac = input("machine2_mac >>")
        
    while True:
        sendp( Ether()/ARP() )
        sleep(5)


def parse_command(command):
    if command == "0":
        parser.print_help()
        print_menu()
    if command == "1":
        get_network_users_ARPSCAN()
    if command == "2":
        ARP_poison()
    if command == "3":
        quit()

def CLI():
    command = input(">>")
    parse_command(command=command)


def main():
    print_banner()
    print_menu()
    while True:
        CLI()
    

if __name__=="__main__":
    main()