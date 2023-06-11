# ARPP

## Configuration
When entering into the Oracle VM Administrator, we need to modify the configurations from each virtual machine.
- First, go to the tools section and create a new NAT network that is going to be used by the three virtual machines (check out the box for DHCP if you are within TU/e network).
- Afterwards, go to the settings of a virtual machine, select network and change the adapter from Host-only to NAT network (which automatically selects the network we have previously created). Still in the network settings, change the type of adater to FAST III and allow VMs in the promiscuous mode. 
- Repeat step 2 with the other two virtual machines.

## Execution
- Open all three machines
- Open a terminal in M3:
    - Go to the folder where the project is saved: <sub>cd ARPP</sub>
    - Execute the lastest version of the project: 'sudo python ARPP_V!.0.4.py'
    - Now, we can see the menu of the possible actions to do:
        - menu: show all the actions
        - 
