#!/usr/bin/env python

# pcap extractor Module
# Made modular code of my pcap.py script for better integration with outside codes
#Coded by Amey Gat (contact@ameygat.com)
#Some base code for dpkt taken from https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
#HTTP url extraction Idea by: https://github.com/RahulBinjve
#Dependancies (Libraries needed)
#  socket 
#sudo pip install dpkt
#sudo pip install netaddr

import dpkt
import sys
import socket
from netaddr import *



#import pdb #Only debug purpose

# Function get_public_IPs(pcap,protocols = ['TCP','UDP','ICMP']): 
# Parameters
# pcap :: dpkt object created by using dpkt.pcap.Reader()
# protocols::  list of protocols to extract IP addresses from 
# unwanted_ip :: list of IP address to ignore
# OUTPUT:
# list of IP address in String format
def get_public_IPs(pcap,protocols = ['TCP','UDP','ICMP'],unwanted_ip = ['0.0.0.0','255.255.255.255']):
    cnt = 0
    ip_list = []

    for timestamp, buf in pcap.readpkts():
        #Some times buf contains \x00 so this checks skip them 
        cnt +=1
        if buf == '\x00\x00\x00\x00':
            #Some pcap files have bytes 00 in beginning, just discard them
            continue
        else:
	        eth = dpkt.ethernet.Ethernet(buf)
	        ip = eth.data
	        tcp = ip.data
	        if tcp.__class__.__name__ in protocols:
		    srcip = IPAddress(socket.inet_ntoa(ip.src))
		    dstip = IPAddress(socket.inet_ntoa(ip.dst))
		    if (srcip.format() not in ip_list) and (srcip.is_unicast() and not srcip.is_private()) and (srcip.format() not in unwanted_ip) :
			    ip_list.append(srcip.format())
		    if (dstip.format() not in ip_list) and (dstip.is_unicast() and not dstip.is_private()) and (dstip.format() not in unwanted_ip):
			    ip_list.append(dstip.format())
    return ip_list

def get_domain_res(pcap,protocols = ['TCP','UDP']):
    cnt = 0
    dns_list = []
    for timestamp, buf in pcap.readpkts():
        #Some times buf contains \x00 so this checks skip them 
        cnt +=1
        if buf == '\x00\x00\x00\x00':
            #Some pcap files have bytes 00 in beginning, just discard them
            continue
        else:
	        eth = dpkt.ethernet.Ethernet(buf)
	        ip = eth.data
	        tcp = ip.data

	        if tcp.__class__.__name__ in protocols:
		        if tcp.sport == 53 or tcp.dport == 53:
			        if eth.type == 2048 and ip.p == 17 :
				        try:
					        dns = dpkt.dns.DNS(tcp.data)
				        except:
					        #print "Error:DNS"
                				continue # Discard errornous Data
				        if dns.qr == dpkt.dns.DNS_R and dns.opcode == dpkt.dns.DNS_QUERY and dns.rcode == dpkt.dns.DNS_RCODE_NOERR:
					        if len(dns.an) >= 1:
					            for answer in dns.an:
						        str1=""
						        if answer.type == 1: #DNS_A
					            		str1 = "A::%s->%s" % (answer.name,socket.inet_ntoa(answer.rdata))
						        elif answer.type == 5:  # "CNAME request"
							        str1 = "CN::%s->%s" % (answer.name,answer.cname)
           						elif answer.type == 12:
             							#print "PTR request", answer.name, "\tresponse", answer.ptrname
							        str1 = "PTR::%s->%s" % (answer.name,answer.ptrname)
						        if str1<> "" : dns_list.append(str1)
    return dns_list    

#http_ports = [80, 8080] # Add other ports if you website on non-standard port.




def get_urls(pcap,protocols = ['TCP'],http_ports = [80, 8080]):
    cnt = 0
    #Initialisation of output variable lists
    urls = []
    for timestamp, buf in pcap.readpkts():
        #Some times buf contains \x00 so this checks skip them 
        cnt +=1
        if buf == '\x00\x00\x00\x00':
            #Some pcap files have bytes 00 in beginning, just discard them
            continue
        else:
	        eth = dpkt.ethernet.Ethernet(buf)
	        ip = eth.data
	        tcp = ip.data
	        if tcp.__class__.__name__ in protocols:
                    if tcp.dport in http_ports and len(tcp.data) > 0:
                        try:
                            http = dpkt.http.Request(tcp.data)
                            urls.append(http.headers['host'] + http.uri)
                        except Exception as e:
                            # Just in case we come across some stubborn kid.
                            print "[-] Some error occured. - %s" % str(e)
                            #continue
    return urls

def main():
    #Get parameter as pcap file
    f = open(sys.argv[1], "r")
    pcap = dpkt.pcap.Reader(f)

    #import pdb
    #pdb.set_trace()    

    urls = get_urls(pcap)
    print "[+] URLs extracted from PCAP file are:"
    for url in urls:
        print url

    #pdb.set_trace()    

    ip_list = get_public_IPs(pcap)    
    print "[+] Public IP addresses from Pcap file:"
    for ip in ip_list:
        print ip

    #pdb.set_trace()    

    dns_list = get_domain_res(pcap)
    print "[+] Domain Resolutions from Pcap file:"
    for dn in dns_list:
        print dn

    #pdb.set_trace()    


    f.close()
if __name__ == "__main__":
    main()
