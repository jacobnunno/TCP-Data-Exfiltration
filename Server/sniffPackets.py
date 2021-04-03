 #! /usr/bin/env python3
import socket
import pcapy as p
from scapy.all import sniff, PcapWriter
import subprocess


def readPcapFile(pcap_file):
    result = subprocess.run(["tshark", "-r", "{}".format(pcap_file)], stdout=subprocess.PIPE)
    lines = (result.stdout.decode('utf-8')).splitlines()
    print("text file output:")

    decimal_list = []
    line_counter = 0
    amount_of_incoming_packets = 0

    for i in lines:
        print(i)
        if line_counter != 0 and line_counter != 1 and line_counter != len(lines):
            substring = "TCP Retransmission"
            if substring in i:
                #if it is a retransmission
                x = i.split("Retransmission] ")
                tcp_source_port = (x[1])[0 : 5]
                #print("source port = {}".format(tcp_source_port))
                decimal_list.append(tcp_source_port)
            else:
                #if there it is not a retransmission
                x = i.split("TCP 60 ")
                tcp_source_port = (x[1])[0 : 5]
                #print("source port = {}".format(tcp_source_port))
                if tcp_source_port != "32768":
                    decimal_list.append(tcp_source_port)
        elif line_counter == 1:
            x = i.split("TCP 60 ")
            amount_of_incoming_packets = (x[1])[0 : 1]
            is_first_packet = 1
        line_counter += 1

    return decimal_list, amount_of_incoming_packets

def receiver_tcp(tcp_ip, tcp_port, amount_of_packets_captured, echo=True, buffer_size=4096):
    src_ip = "192.168.30.128"

    pkts = sniff(filter="tcp and dst {} and src {}".format(tcp_ip, src_ip), count=amount_of_packets_captured)
    my_pcap = PcapWriter("capture.pcap")
    my_pcap.write(pkts)
    print(pkts)
    my_pcap.close()

def main():
    print("are we going to find TCP packets? lets see:")
    number_of_packets = 100
    receiver_tcp("192.168.30.129", 5443, number_of_packets)
    decimal_list, amount_of_incoming_packets = readPcapFile("capture.pcap")

    #print(decimal_list)
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

    print(binary_list)  
    print("Expected amount of packets: {}".format(amount_of_incoming_packets))

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

    print(ascii_string)


if __name__ == "__main__":
    main()
