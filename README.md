# Data Exfiltration Through TCP Source Port
 
Exfiltration via storing data in the TCP source port is a serious threat that can go undetected because of the nature of a randomly generated TCP source port, the covertness of the traffic pattern, and the lack of detecting tools. It has been largely overlooked by researchers presumably because this type of exfiltration cannot cross NAT or proxy devices which are prevalent in modern systems. This research aims to demonstrate the feasibility of exfiltrating data via the TCP source port and to show how difficult it is to detect. 

Based on our research, TCP source port has been overlooked and no techniques have been proposed to detect such traffic. We created a proof of concept to demonstrate the possibilities of exfiltration using the TCP source port. We propose three different variants of this technique. We have also outlined a well design camouflage technique which aims to hide tracks by mimicking a common server-down situation. We tested the proof of concept with the use of SNORT IDS/IPS but were never able to detect the exfiltration except when using a very generic rule that would be infeasible in production because it captures almost all legitimate traffic as well. 
Based on the proof of concept (POC), exfiltration via TCP source port is feasible. It is extremely hard to detect especially when mimicking server-down situations and cannot be differentiated from normal traffic. The main limitation is having NAT/PAT or proxy devices in the path of the traffic, however, public servers that use static NAT will be the ultimate exit points for TCP source port exfiltration.


SendPacket.py
The victim machine’s program is fairly simple. It has two jobs to do, first convert the data within the text file into a list of decimal numbers, and second, craft packets and send them. The program starts by calling the file_to_decimal() function. This function opens and reads the file line by line, converts each line to binary, and saves the binary lines to the variable: list_of_binary. The function then loops through the list adding leading zeros where they are necessary. To find out more as to why each binary string needs to have leading zeros to fill 8 bits, please read the “Text Conversion” section. Once the leading zeros are added, the function loops through the list again and combines the binary strings of 8bits long together to make a list of binary strings 16bits long. If the original list has an odd number of binary strings, then we add a final binary string of “00000000”. This will not change the results of the data transfer as when the receiving end unpacks the binary, “00000000” will not convert to anything. While the function is combining the 8bit binary strings, it will also convert the combined strings to decimal. The file_to_decimal() then returns the list of decimal numbers ready to be set as source ports.

Returning to the main() function, it now has everything it needs to send the packets. The first packet it sends is created with the special source port number of 32,768 and is passed to the send_packet() function. The send_packet() function is a helper function that takes all the information passed to it to create and send the packet. The main() function will call this function whenever it is sending packets. The second packet that the main function creates is one with a unique identifier for the file that is being sent. Currently, our program is picking a random number between 32,768 and 65,535. The third packet sets the source port as the length of our source port list created by the file_to_decimal() function. This is indicating how many packets will be sent. It will then loop through the list of source ports and send them one at a time. Every third packet sent, there is a timer to wait a certain number of seconds depending on how the wait time is set. Once all the data has been sent, the main() function crafts and sends the last packet with our special source port number of 32,768.

sniffPackets.py

The server side of the program is a little more complicated. It also has two general functionalities. The first is to sniff and receive the packets, and the second is process the packets received back into readable data.

The main() function is the focal point of the program that calls one at a time each helper function supplying them with the information that is needed. Main() starts by calling the receiver_tcp() function and passing it the server IP address and the source port to listen on.
	
Receiver_tcp() is the area where the sniffer lives. The function starts by initializing the sniffer and passing it the appropriate arguments such as the source IP, destination IP and protocol to listen for. The sniffer is also passed a function that determines if it is time to stop sniffing. This function is called the stopfilter(). It is a very simple function that returns true or false depending on if it is the second time a packet with our special source port number 32,768 has been sniffed. If it is, then it will return true, signalling the sniffer to stop. Once the sniffer is stopped with the stopfilter() function, it exports the packets gathered to a pcap file.
	
Now that we have the packets saved, the main() function calls the read_pcap_file() function to parse the file. The read_pcap_file() starts by using Wireshark command line to read the pcap file to the command line where we save it. It then loops through all the packets in the file and does multiple functions. First, if the line number is less than ten, it will print the packet to the console. This lets us view the first 10 packets that were received. The loop will then gather all the important information it needs from the packets. It will first skip the first line, where we know the first packet has our special port number and save the unique identifier for the file from the second packet. It will then move to the third packet where it will save the expected number of packets to be received. After the third line, with the use of regex, it will extract and save all the source ports to a list. Once the loop is done, read_pcap_file() will return to the main() function the list of source ports, the unique file identifier taken from the second packet, the expected amount of packets to be received that was taken from the third packet, and the real amount of packets that was received.
	
The main() function has one more function to call before it can output the results: convert_sourceport_to_string(). Main() passes the list that it received from read_pcap_file() to convert_sourceport_to_string(). This function performs the job of converting the source ports back to readable ascii. It first converts each item in the decimal list into binary. It then loops through again and adds leading zeros until the binary number is 16bits long. Now it can loop through again and split the 16bit binary string into two 8bit binary strings which represent our single characters. As the final function, it loops through once more and converts the 8bit binary strings into ascii and concatenates them to a string. The string is then returned to the main() function.
	
Finally main() has everything it needs to output the results of the packet sniffing. It first outputs the expected number of packets and the actual number of packets received. It does a check to see if they are equal and if they are not, outputs a warning about potential lost packets. It then outputs the unique identifier for this set of data and finally finishes by outputting the ascii string containing the data that was exfiltrated.


Instructions to Run the Proof-Of-Concept Code

Environment Set-Up
	
To test the proof of concept, you must first set up the machines that will be used as the server and the victim. We used Kali Linux and Ubuntu. Next, there are three programs that the project will need to work: python3, Wireshark, and Scapy. Python3 and Scapy must be installed on both machines and Wireshark on the adversary server. 

Running the Code

Download the GitHub repository: 

https://github.com/jacobnunno/TCP-Data-Exfiltration

There are two folders within the GitHub repository: Server and Victim. Each folder should be moved to the correct machine. Now we must set up the proper settings to send and receive the packets. Edit both sendPacket.py and sniffPackets.py and change these variables to match your machine’s information:

sendPacket.py

main()

	sourceIP

	destinationIP

	file_to_be_exfiltrated

sniffPackets.py 

main()

	dst_ip
	
receiver_tcp()

	src_ip
	
	
Now it is possible to run the programs. First start by running the sniffPackets.py:

	sudo python3 sniffPackets.py


Second run sendPacket.py to create and send the packets with information from inside the file that was specified.

	sudo python3 sendPacket.py
