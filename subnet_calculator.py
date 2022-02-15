#!/usr/bin/python3

# subnetCalc.py: Subnet calculator for classful & classless IPv4 addresses.

########################
# Function Definitions #
########################

#------------------#
# Common Functions #
#------------------#

#-- Print an informative message
def pr_info(message):
  print(message)
  exit(0)

#-- Convert an IPv4 address to a 32-bit binary number
def ip_to_bin(ip, join=True):
  splitIP = ip.split(".")
  octetBin = []
  if len(splitIP) != 4:
    pr_info("[-] Please provide a valid IPv4 address.")
  else:
    try:
      for octet in splitIP:
        if int(octet) >= 0 and int(octet) <= 255:
          octet = bin(int(octet))[2:]
        else:
          pr_info('[-] Not a valid IPv4 address.')
          
        if len(octet) < 8:
          octet = '0' * (8-len(octet)) + octet
        octetBin.append(octet)
        
    except ValueError:
      pr_info("[-] You have to provide a numeric IPv4 address.")
    
    if octetBin and join == True:
      return ''.join(octetBin)
    
    if octetBin and join == False:
      return octetBin

#-- Convert a 32-bit binary number to a dotted decimal IPv4 address
def bin_to_ip(bin, join=True):
  if len(bin) != 32:
    pr_info("[-] Please provide a valid 32-bit binary number.")
    
  else:
    decOctList = []
    ind1 = 0
    ind2 = 8
    
    try:
      for i in range(4):
        decOctList.append(bin[ind1:ind2])
        decOctList[i] = int(decOctList[i], base=2)
        ind1 += 8
        ind2 += 8
    except ValueError:
      pr_info("[-] Only 1's & 0's are accepted as a 32-bit binary number.")
    
    if join == True:
      for j in range(4):
        decOctList[j] = str(decOctList[j])
      return '.'.join(decOctList)
    else:
      return decOctList

#---------------------#
# Classful Subnetting #
#---------------------#

#-- Count the 'ones' & 'zeroes' in a 32-bit binary number
def count_01(ipBin):
  if len(ipBin) != 32:
    pr_info("[-] A 32-bit binary number is required.")
  else:
    onesCount = 0
    zeroesCount = 0
    for bit in ipBin:
      if bit == '1':
        onesCount += 1
      elif bit == '0':
        zeroesCount += 1
      else:
        pr_info("[-] Only 32-bit binary numbers are accepted.")
        
  count = (onesCount,zeroesCount)
  return count

#-- Determining the class & default subnet mask of an IPv4 address
def class_subMsk(ip, dec=True, outClass=False):
  subMask = 'NA'
  ipBin = ip_to_bin(ip, join=True)
  if ipBin[0] == '0':
    subMask = '1'* 8 + '0' * 24 # 8/24
  elif ipBin[1] == '0':
    subMask =  '1'* 16 + '0' * 16 # 16/16
  elif ipBin[2] == '0':
    subMask = '1'* 24 + '0' * 8 # 24/8
  elif ipBin[3] == '0':
    print("Class D Address: IP multicasting")
  else:
    print("Class E Address: Experimental use")
    
  if dec == False and outClass == False:
    return subMask
  
  elif len(subMask) == 32 and (dec == True or dec == False) and outClass == False:
    return bin_to_ip(subMask, join=True)
    
  elif len(subMask) == 32 and (dec == True  or dec == False) and outClass == True:
    netPortion = count_01(subMask)[0]
    if netPortion == 8:
      return("Class A address: 8/24")
    elif netPortion == 16:
      return("Class B address: 16/16")
    elif netPortion == 24:
      return("Class C address: 24/8")

  else:
    return subMask

#-- Determining the custom subnet mask for a classful IPv4 address
def get_subMsk(ip, subnetBits, slash=False):
  
  # Determine the default class subnet mask
  ipDefSubMask = class_subMsk(ip, dec=False)
  
  # Determine the network and host portion
  if ipDefSubMask != 'NA':
    netPortion = count_01(ipDefSubMask)[0]
    hostPortion = count_01(ipDefSubMask)[1]
    # Determine the subnet ID bits limits according to the class
    subnetBitsLim = list(range(hostPortion))[:-1]
    
    if subnetBits in subnetBitsLim:
      subnetID = '1' * subnetBits
      hostID = '0' * (hostPortion - subnetBits)
      subnetMask = '1' * netPortion + subnetID + hostID
      
      if slash==False:
        return bin_to_ip(subnetMask, join=True)
      else:
        prefixLen = netPortion + len(subnetID)
        return bin_to_ip(subnetMask, join=True) + "/" + str(prefixLen)
    
    else:
      pr_info("[-] Incorrect number of subnet ID bits.")

#-- Count subnets & hosts
def classful_count(ip, subnetBits=0):
  classSubMask = class_subMsk(ip, dec=False)
  if classSubMask != 'NA':
    hostBitsCount = count_01(classSubMask)[1]
    if subnetBits >= 0 and subnetBits <= hostBitsCount - 2:
      subnetNum = 2 ** subnetBits
      hostNum = 2**(hostBitsCount - subnetBits) - 2
      # if hostNum < 2:
      #   pr_info('[-] Minimum number of hosts/subnet is no less than 2')
      # else:
      countDict = {"Total subnets":subnetNum,"Total hosts/subnet":hostNum}
      return countDict
    else:
      pr_info("[-] You're allowed from 0 to " + str(hostBitsCount - 2) + " bits for the subnet ID.")
  else:
    countDict = {"Total subnets":0,"Total hosts/subnet":0}
    return countDict

#-- Determining the subnet ID & the corresponding address
def get_subnet_id(ip, subnetBits=0, subnetNum=0, dec=True):
  ipBin = ip_to_bin(ip)
  defSubMsk = class_subMsk(ip, dec=False)
  if len(defSubMsk) == 32:
    netCount = classful_count(ip,subnetBits)
    totSubnets = netCount['Total subnets']
    
    if subnetBits == 0:
      if dec == True:
        return ip
      else:
        return ipBin
    
    elif subnetBits > 0 and (subnetNum >= 0 and subnetNum < totSubnets):
      netBitsLen = count_01(defSubMsk)[0] # 1's
      ID0 = '0' * subnetBits
      IDNumBin = bin(subnetNum)[2:]
      subnetNumBin = ID0[0:subnetBits - len(IDNumBin)] + IDNumBin
      subnetIDNumBin = ipBin[0:netBitsLen] + subnetNumBin + '0' * (32-netBitsLen-subnetBits)
    
      if  dec == True:
        return(bin_to_ip(subnetIDNumBin))
      else:
        return subnetIDNumBin
        
    else:
      pr_info("[-] You're allowed to check from 0 up to " + str(totSubnets-1) + " subnet ID.")
  
  if defSubMsk == 'NA':
    pr_info("[+] Subnetting can't be done on either class D (multicasting) or E (Experimental).")
  
#-- Determining the host address for each subnet ID
def get_sub_hostAdd(ip, subnetBits=0, subnetNum=0, hostID=0):
  subBaseAddr = get_subnet_id(ip, subnetBits, subnetNum, dec=True)
  baseAddClass = class_subMsk(subBaseAddr, dec=False)
  if len(baseAddClass) == 32:
    netCount = classful_count(ip,subnetBits)
    # totSubnets = netCount['Total subnets']
    hostsPerSubnet = netCount['Total hosts/subnet']
    if hostID > 0 and hostID <= hostsPerSubnet:
      subBaseAddrBin = ip_to_bin(subBaseAddr)
      netBits = count_01(baseAddClass)[0] # 1's
      hostBits = count_01(baseAddClass)[1] # 0's
      netPortion = subBaseAddrBin[0:netBits]
      hostPortion = subBaseAddrBin[32-hostBits:]
      subnetIDBits = hostPortion[0:subnetBits]
      hostIDBits = hostPortion[len(subnetIDBits):]
      hostIDBin = bin(hostID)[2:]
      hostIDBits = hostIDBits[0:len(hostIDBits)-len(hostIDBin)] + hostIDBin
      hostIDAdd = netPortion + subnetIDBits + hostIDBits
      return bin_to_ip(hostIDAdd)
    
    elif hostID < 0:
      pr_info("[-] Can't check a negative number of hosts.")
    
    elif hostID == 0:
      return(subBaseAddr)
    
    else:
      pr_info("[-] Maximum of " + str(hostsPerSubnet) + " host addresses can be checked.")
      
#-----------------------------#
# Classless Subnetting (CIDR) #
#-----------------------------#

#-- Count total number of subnets and hosts/subnet for a given prefix length
def classless_count(prefLen):
  if prefLen >= 1 and prefLen <= 30:
    netPortion = 2 ** prefLen
    hostPortion  = 2 ** (32 - prefLen) - 2
    countDict = {'Subnets tot. #':netPortion, 'Hosts/subnet':hostPortion}
    return countDict
  else:
    pr_info("[-] You're allowed from 1 to 30 bits for the prefix length (network portion).")

#-- CIDR hierarchical division
def div_net(ip, prefLen, subNetBits=0, dec=True):

  # Convert the main IP to binary
  ipBin = ip_to_bin(ip)
  
  # Total subnet IDs 
  subnetIDs = []
  subnetIDsBin = []
  
  # Full network in slash notation
  fullNet = ip + "/" + str(prefLen)
  
  # Total hosts per the corresponding subnet
  hostNum = classless_count(prefLen)['Hosts/subnet']
  
  # Determine the network & host portion for the classless address
  netPortion = ipBin[0:prefLen]
  hostPortion = ipBin[prefLen:]
  
  # Checking for incorrect subnet bits number
  if subNetBits < 0 or subNetBits > 32-prefLen:
    pr_info("[-] You're allowed to take 0 up to " + str(32-prefLen) + " subnet bits from the host ID.")
  
  # Determining the corresponding subnet ID addresses
  subNetCount = 2 ** subNetBits
  prefLen += subNetBits
  for ID in range(subNetCount):
    subIDBin = bin(ID)[2:]
    if len(subIDBin) < subNetBits:
      subIDBin = '0' * (subNetBits - len(subIDBin)) + subIDBin
    subIDAddBin = netPortion + subIDBin + hostPortion[len(subIDBin):]
    subnetIDsBin.append(subIDAddBin)
    subnetIDs.append(bin_to_ip(subIDAddBin) + "/" + str(prefLen))
     
  if dec==True:
    return subnetIDs
  else:
    return subnetIDsBin
    
############################
# Function Definitions End #
############################
