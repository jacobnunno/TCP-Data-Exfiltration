 #! /usr/bin/env python3

from scapy.all import *
import codecs
import sys


def fileToDecimal():
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
        i += 1 
    print(list_of_binary)
    finished_decimal_list = []
    j = 0
    while j < len(list_of_binary): 
        if (j % 2) == 0:
            temp = int(list_of_binary[j] + list_of_binary[j+1], 2)
            finished_decimal_list.append(temp)
        j += 1 

    print(finished_decimal_list)  
    return finished_decimal_list



def main():
    list_of_decimal = fileToDecimal()

    sourceIP = "192.168.30.128"
    destinationIP = "192.168.30.129"

    for i in list_of_decimal:
        #create and send the packets
        packet = IP()/TCP(dport=5433, sport=int(i))
        packet.src = sourceIP
        packet.dst = destinationIP
        print(packet.summary())
        send(packet)

if __name__ == "__main__":
    main()