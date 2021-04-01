 #! /usr/bin/env python3
import socket
import pcapy as p
from scapy.all import sniff, PcapWriter
import subprocess


def replaceEights(binary_list):
    i = 0
    while i < len(binary_list): 
        # replace the 8s with 0s so that we can save them as ints and 
        binary_list[i] = binary_list[i].replace("8", "0") 
        i += 1 
    return binary_list


def readPcapFile(pcap_file):
    result = subprocess.run(["tshark", "-r", "{}".format(pcap_file)], stdout=subprocess.PIPE)
    lines = (result.stdout.decode('utf-8')).splitlines()
    print("text file output:")

    binary_list = []

    for i in lines:
        print(i)
        substring = "TCP Retransmission"
        if substring in i:
            #if it is a retransmission
            x = i.split("Retransmission] ")
            tcp_source_port = (x[1])[0 : 4]
            #print("source port = {}".format(tcp_source_port))
            binary_list.append(tcp_source_port)
        else:
            #if there it is not a retransmission
            x = i.split("TCP 60 ")
            tcp_source_port = (x[1])[0 : 4]
            #print("source port = {}".format(tcp_source_port))
            binary_list.append(tcp_source_port)

    return binary_list

def receiver_tcp(tcp_ip, tcp_port, amount_of_packets_captured, echo=True, buffer_size=4096):
    src_ip = "192.168.30.128"

    pkts = sniff(filter="tcp and dst {} and src {}".format(tcp_ip, src_ip), count=amount_of_packets_captured)
    my_pcap = PcapWriter("capture.pcap")
    my_pcap.write(pkts)
    print(pkts)
    my_pcap.close()

def main():
    print("are we going to find TCP packets? lets see:")
    number_of_packets = 16
    receiver_tcp("192.168.30.129", 5443, number_of_packets)
    binary_list = readPcapFile("capture.pcap")
    binary_list = replaceEights(binary_list)

    print(binary_list)
    #combine the 4 bits together to get 8 bits

    finished_binary_list = []
    i = 0
    while i < len(binary_list): 
        if (i % 2) == 0:
            finished_binary_list.append(binary_list[i] + binary_list[i+1])
        i += 1 

    print(finished_binary_list)

    ascii_string = ""

    for binary_eight_item in finished_binary_list:
        an_integer = int(binary_eight_item, 2)
        ascii_character = chr(an_integer)
        ascii_string += ascii_character

    print(ascii_string)

    print("Done!")





if __name__ == "__main__":
    main()