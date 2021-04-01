 #! /usr/bin/env python3

from scapy.all import *
import codecs
import sys


def fileToBinary():
    file = open('testFile.txt')
    content = file.read() 
    file.close()
    binary_of_file_content = ' '.join(format(ord(x), 'b') for x in content)

    #splitting it to a list
    list_of_binary = binary_of_file_content.split()
    i = 0
    while i < len(list_of_binary): 
        while len(list_of_binary[i]) < 8:
            list_of_binary[i] = "0" + list_of_binary[i]
        # replace the 0s with 8s so that we can save them as ints and 
        #    send it as the source port
        list_of_binary[i] = list_of_binary[i].replace("0", "8") 
        i += 1 

    return list_of_binary



def main():

    list_of_binary = fileToBinary()

    sourceIP = "192.168.30.128"
    destinationIP = "192.168.30.129"

    for i in list_of_binary:
        #split the bits into two
        first_half = i[0:4]
        second_half = i[4:9]
        #print(first_half)
        #print(second_half)
        #create and send the packet 1
        first_half_packet = IP()/TCP(dport=5433, sport=int(first_half))
        first_half_packet.src = sourceIP
        first_half_packet.dst = destinationIP
        print(first_half_packet.summary())
        send(first_half_packet)

        #create and send the packet 2
        second_half_packet = IP()/TCP(dport=5433, sport=int(second_half))
        second_half_packet.src = sourceIP
        second_half_packet.dst = destinationIP
        print(second_half_packet.summary())
        send(second_half_packet)

if __name__ == "__main__":
    main()