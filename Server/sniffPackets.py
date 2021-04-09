 #! /usr/bin/env python3
 #Author: Giacomo Nunno


import socket
import pcapy as p
from scapy.all import sniff, PcapWriter
from scapy.layers.inet import TCP
import subprocess
import re

#variable for checking for second instance of a packet with 32768
start_packet_received = False

def stopfilter(x):
    #reason for the snifer to stop. Stops the second time is sees port 32768
    global start_packet_received
    if x[TCP].sport == 32768:
        if start_packet_received:
            return True
        else:
            start_packet_received = True
            return False
    else:
        return False


def read_pcap_file(pcap_file):
    #read the pcap file
    result = subprocess.run(["tshark", "-r", "{}".format(pcap_file)], stdout=subprocess.PIPE)
    lines = (result.stdout.decode('utf-8')).splitlines()
    print("First 10 Packets Received:")

    decimal_list = []
    line_counter = 0
    amount_of_incoming_packets = 0

    #Go through the file line by line
    for i in lines:
        #print the first 10 lines
        if line_counter < 10:
            print(i)
        #extract the source port with the use of regex
        if line_counter != 0 and line_counter != 1 and line_counter != len(lines):
            substring = "TCP Retransmission"
            if substring in i:
                #if it is a retransmission
                result = re.search('Retransmission] (.*) →', i)
                tcp_source_port = result.group(1)
                if tcp_source_port != "32768":
                    decimal_list.append(tcp_source_port)
            else:
                #if there it is not a retransmission
                result = re.search('TCP 60 (.*) →', i)
                tcp_source_port = result.group(1)
                if tcp_source_port != "32768":
                    decimal_list.append(tcp_source_port)
        elif line_counter == 1:
            #if it is the second packet, then we know that it is the amount of packets to be sent
            result = re.search('TCP 60 (.*) →', i)
            amount_of_incoming_packets = result.group(1)
            is_first_packet = 1
        line_counter += 1
    # subtract 3 for the first and last and the expected amount packet
    return decimal_list, amount_of_incoming_packets, line_counter - 3

def receiver_tcp(tcp_ip, tcp_port, echo=True, buffer_size=4096):
    src_ip = "192.168.xx.xxx"
    temp_file_name = "capture.pcap"
    #start sniffer
    pkts = sniff(filter="tcp and dst {} and src {}".format(tcp_ip, src_ip), stop_filter=stopfilter)
    my_pcap = PcapWriter(temp_file_name)
    #write to file
    my_pcap.write(pkts)
    #print the packets that are being sent
    print(pkts)
    my_pcap.close()
    return temp_file_name

def convert_sourceport_to_string(decimal_list):
    #convert decimal to binary
    binary_list = []
    i = 0
    while i < len(decimal_list): 
        temp = "{0:08b}".format(int(decimal_list[i]))
        binary_list.append(temp)
        i += 1 

    j = 0
    #ADD the leading 0S
    while j < len(binary_list): 
        while len(binary_list[j]) < 16:
            binary_list[j] = "0" + binary_list[j]
        j += 1

    #split each binary string into 2 strings, so 2 characters
    finished_binary_list = []
    k = 0
    while k < len(binary_list): 
        firstpart, secondpart = (binary_list[k])[:len((binary_list[k]))//2], (binary_list[k])[len((binary_list[k]))//2:]
        finished_binary_list.append(firstpart)
        finished_binary_list.append(secondpart)
        k += 1

    ascii_string = ""

    #convert binary to ascii
    for binary_list_item in finished_binary_list:
        an_integer = int(binary_list_item, 2)
        ascii_character = chr(an_integer)
        ascii_string += ascii_character
    return ascii_string


def main():
    print("Packet Sniffer Started")
    dst_ip = "192.168.xx.xxx"
    pcap_file_name = receiver_tcp(dst_ip, 5443)
    decimal_list, expected_amount_of_packets, amount_of_packets_received = read_pcap_file(pcap_file_name)
    ascii_string = convert_sourceport_to_string(decimal_list)

    #print results
    print("Expected amount of packets: {}".format(expected_amount_of_packets))
    print("Actual amount of packets: {}".format(amount_of_packets_received))
    if int(expected_amount_of_packets) != int(amount_of_packets_received):
        print("Expected amount and actual amount differ.  Packets have been lost.")
    print("Data Received:")
    print(ascii_string)


if __name__ == "__main__":
    main()
