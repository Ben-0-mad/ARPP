# ARPP

## Configuration
When entering into the Oracle VM Administrator, we need to modify the configurations from each virtual machine.
First, go to the tools section and create a new NAT network that is going to be used by the three virtual machines (check out the box for DHCP if you are within TU/e network).
Afterwards, go to the settings of a virtual machine, select network and change the adapter from Host-only to NAT network (which automatically selects the network we have previously created). Still in the network settings, change the type of adater to FAST III and allow VMs in the promiscuous mode. Reapeat this step with the other 2 virtual machines.

## Execution
