# ARPP

## Configuration
When entering into the Oracle VM Administrator, we need to modify the configurations from each virtual machine.
- First, go to the tools section and create a new NAT network that is going to be used by the three virtual machines (check out the box for DHCP if you are within TU/e network).
- Afterwards, go to the settings of a virtual machine, select network and change the adapter from Host-only to NAT network (which automatically selects the network we have previously created). Still in the network settings, change the type of adater to FAST III and allow VMs in the promiscuous mode. 
- Repeat step 2 with the other two virtual machines.

## Execution
- Open all three machines
- Open a terminal in M3:
    - Go to the folder where the project is saved: `cd ARPP`
    - Execute the lastest version of the project: `sudo python ARPP_V1.0.4.py`
    - Now, we can see the menu of the possible actions to do:
        - menu: show all the actions
        - help: help function
        - scan local network for users: looks for all the devices connected to the local network (need to specify interface if it is not chosen already)
        - select interface: selects the interface we want to work on
        - arp poison: poison the ARP tables from two devices of our selection. Select the interface (if not done yet) and provide the IP addresses of the victim's device and the device you want to spoof
        - arp mitm: Man-In-The-Middle attack. Select the interface (if not done yet) and provide the IP addresses of the devices you want to catch data from their iteractions
        - DNS spoofing: (should have executed arp mitm previously) provide the IP address from the victim to catch data from the requests that the victim does to the DNS server and spoof the IP address of the requested website
        - SSL stripping: ARP poisoning and spoofing for HTTPS requests
        - show running threads: shows all threads that are currently still running
        - end a thread task: select the thread you want to terminate
        - end all threads tasks: terminates all threads that are currently running
        - exit: ends all threads and exit the user interface

- M2: 
    - Since M2 is not in the same interface as M1 and M3, we need to change it's IP address permanently (so we don't have to change its IP address everytime we restart M2). To do so, go to the editor and open the file `/opt/eth0.sh`. Modify its content such that it looks like this:

```
#!/bin/sh

sleep 1
if [ -f /var/run/udhcpc.eth0.pid ]; then
kill `cat /var/run/udhcpc.eth0.pid`
sleep 0.1
fi

ifconfig eth0 <IP address> netmask <Netmask> broadcast <IP address broadcast> up
route add default gw <IP address default gateway>
echo nameserver <IP address broadcast-1> >> /etc/resolv.conf
```

    where the ´<>´ need to be replaced by some IP addresses 
                                                                  
 
    - Open terminal and execute: `ifconfig` (the IP address is the one used to spoof the websites we want that are described on the `.conf` file)
- M1: 
    - Open terminal and execute: `ipconfig` 
         - IP address: is the victim's IP address that we are going to use for the threads in M1
         - Default gateway: is the router's IP address that we are going to use for the threads in M1
    - After performing the DNS spoofing, execute a `ping` to a website from the `.conf` file and see that the IP address that is reaching is the IP address which we have provided (that is, the M2 IP address)
    - Go to Internet Explorer and search for a website from the `.conf` file and see that the displayed website is the *It works!* page from M2
