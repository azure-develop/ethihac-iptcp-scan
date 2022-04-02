#!/usr/bin/evn python

#Import all modules or libraries needed to make this tool work
import nmap
import argparse
import datetime
import sys
import ipaddress
from colorama import Fore, Back, Style

#This function is for ICMP scanning it only accepts one argument which is the IP address(es) 
def ping(tghost):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, arguments = "-sn -PE")
  if nmscan.scanstats()['uphosts']=='1':
    return "open"
  else:
    return "close"

#Function for TCP Connect scanning
def tcpcon(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sT -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='open':
      return "open"
    elif nmscan[str(tghost)].tcp(int(tgport))['state']=='filtered':
      return "filtered"
    else:
      return "close"
  else:
    return "dead"

#Function for TCP SYN scanning
def tcpsyn(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sS -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='open':
      return "open"
    elif nmscan[str(tghost)].tcp(int(tgport))['state']=='filtered':
      return "filtered"
    else:
      return "close"
  else:
    return "dead"

#Function for TCP Xmas scanning
def tcpxmas(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sX -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='open|filtered':
      return "open"
    else:
      return "close"
  else:
    return "dead"
    
#Function for TCP FIN scanning
def tcpfin(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sF -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='open|filtered':
      return "open"
    else:
      return "close"
  else:
    return "dead"
    
#Function for TCP Null scanning
def tcpnull(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sN -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='open|filtered':
      return "open"
    else:
      return "close"
  else:
    return "dead"
    
#Function for TCP ACK scanning
def tcpack(tghost, tgport):
  nmscan = nmap.PortScanner()
  nmscan.scan(tghost, tgport, arguments = "-sA -Pn")
  if tghost in nmscan.all_hosts():
    if nmscan[str(tghost)].tcp(int(tgport))['state']=='filtered':
      return "open"
    else:
      return "close"
  else:
    return "dead"


#This is the main function where most of the code is located. The time it takes the tool to run is found here.
#Accepting user input/command with the help of argparse is also located here.
#Conditional statements as to which scan will be done and the printing of results are here. 
def main():
  try:
    timestart = datetime.datetime.now()
    parser = argparse.ArgumentParser(usage='sudo python3 henmap.py ipadd -p PORT [-options]\nusage: sudo python3 henmap.py [-v | -h]')

    parser.add_argument("ipadd", nargs="?", help = "target ip address or ip address range in CIDR notation")
    parser.add_argument("-p", dest = "port", help = "target port(single) to be scanned")
    parser.add_argument("-v", "--version", dest = "version", help = "CLI tool current version", action = "store_true")
    parser.add_argument("-t", dest = "time", help = "time spent by tool to scan and display", action = "store_true")
  
    args = parser.parse_args()
    tghost = args.ipadd
    tgport = args.port
    singleip = None
    iplist = []
    text = "IP Address"
    yes = "Y"
    no = "N"
    fil = "F"
    dead = "X"
    pipe = Fore.RESET + "|"

#Check user input, sys.argv is what the user types in the CLI
#If user includes option '-v' it will show the current version of this tool
    if sys.argv[1] == '-v' or sys.argv[1] == '--version': 
      print(Fore.RESET + "\nHenmap v2.0 12/1/2020 This is a school project for the course ETHIHAC. It is a ping sweep and port scanner in one coded with python that will display in a table format. This is possible thanks to the open-source module and libraries especially \'python-nmap\' and \'ipaddress\'. Made by "+Fore.CYAN+"Hennry Cai"+Fore.RESET)
    elif sys.argv[1].count('.') == 3 and sys.argv[2] == '-p':
#Check if single ip address or CIDR notation ip address range and store in variable    
      if tghost != None and "/" not in tghost:
        singleip = str(ipaddress.IPv4Address(tghost))
      else:
        network = ipaddress.IPv4Network(tghost, strict=False)
        for ip in network:
          iplist.append(str(ip))
      header = "|{}| ICMP | TCP Connect | TCP SYN | TCP Xmas | TCP FIN | TCP Null | TCP ACK |".format(text.center(16," "))
      vertline = len(header)
      dport = "=   Target Port: " + tgport + "   ="
      vertdport = len(dport)
      eqdport = ""
      for x in range(vertdport): eqdport = eqdport + "="
      print(Style.BRIGHT + "\n" + eqdport.center(int(vertline  ), " "))
      print(dport.center(int(vertline  ), " "))
      print(eqdport.center(int(vertline  ), " ") + "\n")
#Code below is the main output
      for x in range(vertline): print("-", end = "")
      print("\n" + header)
      for x in range(vertline): print("-", end = "")
      if singleip != None:
        if ping(singleip)=="open":
          result = "\n"+pipe+singleip.center(16, " ")+pipe+Fore.CYAN+yes.center(6, " ")+pipe
#Only connect and syn scan are stored in a variable since longer if statements to save time.
          con = tcpcon(singleip, tgport)
          syn = tcpsyn(singleip, tgport)
          if con=="open":
            result = result + Fore.CYAN+yes.center(13, " ") + pipe
          elif con=="filtered":
            result = result + Fore.YELLOW+fil.center(13, " ") + pipe
          else:
            result = result + Fore.RED+no.center(13, " ") + pipe
          if syn=="open":
            result = result + Fore.CYAN+yes.center(9, " ") + pipe
          elif syn=="filtered":
            result = result + Fore.YELLOW+fil.center(9, " ") + pipe
          else:
            result = result + Fore.RED+no.center(9, " ") + pipe
          if tcpxmas(singleip, tgport)=="open":
            result = result + Fore.CYAN+yes.center(10, " ") + pipe
          else:
            result = result + Fore.RED+no.center(10, " ") + pipe
          if tcpfin(singleip, tgport)=="open":
            result = result + Fore.CYAN+yes.center(9, " ") + pipe
          else:
            result = result + Fore.RED+no.center(9, " ") + pipe
          if tcpnull(singleip, tgport)=="open":
            result = result + Fore.CYAN+yes.center(10, " ") + pipe
          else:
            result = result + Fore.RED+no.center(10, " ") + pipe
          if tcpack(singleip, tgport)=="open":
            result = result + Fore.CYAN+yes.center(9, " ") + pipe
          else:
            result = result + Fore.RED+no.center(9, " ") + pipe

          print(result)
          for x in range(vertline): print(Fore.RESET + "-", end = "")
        else:
          oresult = "\n"+pipe+singleip.center(16, " ")+pipe+Fore.RED+no.center(6, " ")+pipe
          con2 = tcpcon(singleip, tgport)
          syn2 = tcpsyn(singleip, tgport)
          xmas2 = tcpxmas(singleip, tgport)
          fin2 = tcpfin(singleip, tgport)
          null2 = tcpnull(singleip, tgport)
          ack2 = tcpack(singleip, tgport)
          if con2=="dead":
            oresult = oresult + Fore.RESET+dead.center(13, " ") + pipe
          elif con2=="open":
            oresult = oresult + Fore.CYAN+yes.center(13, " ") + pipe
          elif con2=="filtered":
            oresult = oresult + Fore.YELLOW+fil.center(13, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(13, " ") + pipe
          if syn2=="dead":
            oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
          elif syn2=="open":
            oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
          elif syn2=="filtered":
            oresult = oresult + Fore.YELLOW+fil.center(9, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(9, " ") + pipe
          if xmas2=="dead":
            oresult = oresult + Fore.RESET+dead.center(10, " ") + pipe
          elif xmas2=="open":
            oresult = oresult + Fore.CYAN+yes.center(10, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(10, " ") + pipe
          if fin2=="dead":
            oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
          elif fin2=="open":
            oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(9, " ") + pipe
          if null2=="dead":
            oresult = oresult + Fore.RESET+dead.center(10, " ") + pipe
          elif null2=="open":
            oresult = oresult + Fore.CYAN+yes.center(10, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(10, " ") + pipe
          if ack2=="dead":
            oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
          elif ack2=="open":
            oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
          else:
            oresult = oresult + Fore.RED+no.center(9, " ") + pipe

          print(oresult)
          for x in range(vertline): print(Fore.RESET + "-", end = "")
      else:
        for ip in iplist:
          if ping(ip)=="open":
            result = "\n"+pipe+ip.center(16, " ")+pipe+Fore.CYAN+yes.center(6, " ")+pipe
            con3 = tcpcon(ip, tgport)
            syn3 = tcpsyn(ip, tgport)
            if con3=="open":
              result = result + Fore.CYAN+yes.center(13, " ") + pipe
            elif con3=="filtered":
              result = result + Fore.YELLOW+fil.center(13, " ") + pipe
            else:
              result = result + Fore.RED+no.center(13, " ") + pipe
            if syn3=="open":
              result = result + Fore.CYAN+yes.center(9, " ") + pipe
            elif syn3=="filtered":
              result = result + Fore.YELLOW+fil.center(9, " ") + pipe
            else:
              result = result + Fore.RED+no.center(9, " ") + pipe
            if tcpxmas(ip, tgport)=="open":
              result = result + Fore.CYAN+yes.center(10, " ") + pipe
            else:
              result = result + Fore.RED+no.center(10, " ") + pipe
            if tcpfin(ip, tgport)=="open":
              result = result + Fore.CYAN+yes.center(9, " ") + pipe
            else:
              result = result + Fore.RED+no.center(9, " ") + pipe
            if tcpnull(ip, tgport)=="open":
              result = result + Fore.CYAN+yes.center(10, " ") + pipe
            else:
              result = result + Fore.RED+no.center(10, " ") + pipe
            if tcpack(ip, tgport)=="open":
              result = result + Fore.CYAN+yes.center(9, " ") + pipe
            else:
              result = result + Fore.RED+no.center(9, " ") + pipe

            print(result)
            for x in range(vertline): print(Fore.RESET + "-", end = "")
          else:
            oresult = "\n"+pipe+ip.center(16, " ")+pipe+Fore.RED+no.center(6, " ")+pipe
            con4 = tcpcon(ip, tgport)
            syn4 = tcpsyn(ip, tgport)
            xmas4 = tcpxmas(ip, tgport)
            fin4 = tcpfin(ip, tgport)
            null4 = tcpnull(ip, tgport)
            ack4 = tcpack(ip, tgport)
            if con4=="dead":
              oresult = oresult + Fore.RESET+dead.center(13, " ") + pipe
            elif con4=="open":
              oresult = oresult + Fore.CYAN+yes.center(13, " ") + pipe
            elif con4=="filtered":
              oresult = oresult + Fore.YELLOW+fil.center(13, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(13, " ") + pipe
            if syn4=="dead":
              oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
            elif syn4=="open":
              oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
            elif syn4=="filtered":
              oresult = oresult + Fore.YELLOW+fil.center(9, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(9, " ") + pipe
            if xmas4=="dead":
              oresult = oresult + Fore.RESET+dead.center(10, " ") + pipe
            elif xmas4=="open":
              oresult = oresult + Fore.CYAN+yes.center(10, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(10, " ") + pipe
            if fin4=="dead":
              oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
            elif fin4=="open":
              oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(9, " ") + pipe
            if null4=="dead":
              oresult = oresult + Fore.RESET+dead.center(10, " ") + pipe
            elif null4=="open":
              oresult = oresult + Fore.CYAN+yes.center(10, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(10, " ") + pipe
            if ack4=="dead":
              oresult = oresult + Fore.RESET+dead.center(9, " ") + pipe
            elif ack4=="open":
              oresult = oresult + Fore.CYAN+yes.center(9, " ") + pipe
            else:
              oresult = oresult + Fore.RED+no.center(9, " ") + pipe

            print(oresult)
            for x in range(vertline): print(Fore.RESET + "-", end = "")
#This is the legend that also gets displayed along with the results so users know what the output means
      print("\n\nICMP:")
      print(Fore.CYAN + "Y: Responds to Echo Requests   " + Fore.RED + "N: No response")
      print(Fore.RESET + "TCP Connect:")
      print(Fore.CYAN + "Y: Port is Open   " + Fore.YELLOW + "F: Port is Filtered   " + Fore.RED + "N: Port is Closed   " + Fore.RESET + "X: Host is down, cannot scan port")
      print(Fore.RESET + "TCP SYN:")
      print(Fore.CYAN + "Y: Port is Open   " + Fore.YELLOW + "F: Port is Filtered   " + Fore.RED + "N: Port is Closed   " + Fore.RESET + "X: Host is down, cannot scan port")
      print(Fore.RESET + "TCP Xmas:")
      print(Fore.CYAN + "Y: Port is Open|Filtered   " + Fore.RED + "N: Port is Closed   " + Fore.RESET + "X: Host is down, cannot scan port")
      print(Fore.RESET + "TCP FIN:")
      print(Fore.CYAN + "Y: Port is Open|Filtered   " + Fore.RED + "N: Port is Closed   " + Fore.RESET + "X: Host is down, cannot scan port")
      print(Fore.RESET + "TCP Null:")
      print(Fore.CYAN + "Y: Port is Open|Filtered   " + Fore.RED + "N: Port is Closed   " + Fore.RESET + "X: Host is down, cannot scan port")
      print(Fore.RESET + "TCP ACK:")
      print(Fore.CYAN + "Y: Firewall  " + Fore.RED + "N: No Firewall   " + Fore.RESET + "X: Host is down, cannot scan port" + Fore.RESET)
      for input2 in sys.argv:
        if input2 == '-t':
#If user includes option '-t' the result will also display time it took the tool from the time they entered the command till before the display
          timeend = datetime.datetime.now()
          timediff = (timeend-timestart).total_seconds()
          print(Fore.RESET + "\nHenmap tool spent " + Fore.GREEN + str(timediff)[:-3] + Fore.RESET + " seconds")
        elif input2 == '-v': 
          print(Fore.RESET + "\nHenmap v2.0 12/1/2020 This is a school project for the course ETHIHAC. It is a ping sweep and port scanner in one coded with python that will display in a table format. This is possible thanks to the open-source module and libraries especially \'python-nmap\' and \'ipaddress\'. Made by "+Fore.CYAN+"Hennry Cai"+Fore.RESET)
    else:
      print("henmap: syntax error: Try command 'python3 henmap -h' to see usage.")
      sys.exit(0)
      
#The whole code in main() is in a try except to catch exceptions/error. 
#First is just to tell user to use 'sudo'
#Second and Third is for incorrect ip address inputted
#Fourth is caused by reading argv list for the conditional statement in main code thus needing restriction on user input.
#Fifth is just to catch 'ctrl-c' from user while tool is running for a cleaner exit
  except nmap.nmap.PortScannerError:
    print("Sorry, this command needs root privileges. Please add \'sudo\' at the start of your command.")
    sys.exit(0)
  except ipaddress.AddressValueError:
    print("Invalid IPv4 address or no IPv4 address inputted. Try again.")
    sys.exit(0)
  except ipaddress.NetmaskValueError:
    print("Invalid IPv4 netmask or no IPv4 CIDR notation inputted. Try again.")
    sys.exit(0)
  except IndexError:
    print("henmap: index error: Sorry, Please try command 'python3 henmap -h' to see usage.")
    sys.exit(0)
  except KeyboardInterrupt:
    print("\nTool stopped by user, results not generated")
    sys.exit(0)    
#This two line 'if statement' is what enables the code to be run in Linux CLI
if __name__ == "__main__":
  main()