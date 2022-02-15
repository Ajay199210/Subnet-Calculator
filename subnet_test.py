#!/usr/bin/python3

# subnet_test.py: A simple script that tests the subnet_calculator program (blueprint)
# to test classful & classless subnetting.

import subnet_calculator, sys, pprint

#-- Check user arguments
if len(sys.argv) != 2 :
  exit("Usage: python3 subnet_test.py <IPv4>") # you can try with 154.71.0.0 as an example

#-- Classful subnetting
v = subnet_calculator.get_subnet_id(sys.argv[1], subnetBits=5, subnetNum=11, dec=True)
print('Subnet ID Address: %s' %v)
v = subnet_calculator.get_sub_hostAdd(sys.argv[1], subnetBits=5, subnetNum=11, hostID=3)
print('Subnet Host Address: %s' %v)

#-- Classless subnetting
v = subnet_calculator.classless_count(3)
print(v)
v = subnet_calculator.div_net(ip=sys.argv[1], prefLen=3, subNetBits=5, dec=False)
pprint.pprint(v)
