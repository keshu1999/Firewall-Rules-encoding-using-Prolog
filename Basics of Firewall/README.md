## How does a Firewall work?

A firewall operates similarly to a security guard at a college gate, inspecting each data packet to assess its origin, destination, or both. Based on this evaluation, the firewall decides whether the packet should be permitted to continue or rejected. In the case of rejection, the packet is either sent back to its source, analogous to a person being turned away at a gate, or it is simply discarded, effectively causing it to cease to exist.

## What is a firewall policy or ruleset?

When implementing a firewall, individuals typically have a clear understanding of its intended purpose. For instance, a firewall may be configured to allow traffic to reach a web server while blocking all other traffic. This objective is an example of a firewall policy. The individual responsible for configuring the firewall, often referred to as a firewall administrator, translates this policy into a series of technical instructions known as a ruleset. This ruleset directs the firewall's hardware or software on how to enforce the policy.

## How to write a Firewall Rule?

The majority of traffic that reaches a firewall consists of Internet Protocol (IP) traffic utilizing one of the three primary Transport Layer protocols: TCP, UDP, or ICMP. Each of these protocols includes a source address and a destination address, which uniquely identify the sending and receiving computers for data packets. Both TCP and UDP protocols utilize port numbers—ranging from 0 to 65,535—to identify the specific application that initiated the connection. For instance, web servers typically use TCP port 80, meaning that a packet destined for a web server would contain the web server's destination address and a destination port number of 80.

In contrast, ICMP does not utilize port numbers; instead, it employs a type code to indicate the purpose of the packet. ICMP is primarily used for diagnosing network issues or notifying systems of problems. For example, when using the ping command, ICMP packets are generated to test the reachability of a host on a network.

TCP packets contain flags that indicate the state of a connection between two hosts. These flags are designated by names such as SYN, FIN, ACK, and RST. A packet intended to initiate a connection will have only the SYN flag set. In contrast, all subsequent communication between the two systems will include the ACK flag.

Firewalls can be configured to identify packets with only the SYN flag set, treating these as attempts to establish new connections, while packets with the ACK flag are assumed to belong to an existing connection. This configuration has important security implications, as the sender of a packet can manipulate the flags present. Nevertheless, this approach serves as an effective initial method for distinguishing between new and existing connections.

## How is the traffic controlled using a Firewall?

Firewalls employ one or more of three primary methods to manage traffic flowing in and out of a network:

- **Packet Filtering**: In this method, packets (small units of data) are analyzed against a predefined set of filters. Packets that successfully pass through these filters are forwarded to the requesting system, while all others are discarded. 
- **Proxy Service**: In this configuration, the firewall retrieves information from the Internet and then transmits it to the requesting system. This process works in both directions, allowing for the secure exchange of information between the Internet and internal systems.
- **Stateful Inspection**: This more advanced method does not analyze the contents of each packet individually. Instead, it compares certain key components of the packet to a database of trusted information. Traffic originating from within the firewall to the outside is monitored for specific defining characteristics, while incoming packets are compared to these characteristics. If the incoming information matches the expected criteria, it is allowed through; otherwise, it is discarded.

## Firewall Configuration
Filters can be added or removed based on several criteria, including:
 
- **IP Addresses:** Each device on the Internet is assigned a unique identifier known as an IP address. IPv4 addresses are 32-bit numbers typically represented as four octets in a dotted-decimal format; for example, 216.27.61.137. If a particular external IP address is accessing files from a server excessively, the firewall can be configured to block all traffic to or from that IP address. Given the rapidly decreasing availability of IPv4 addresses as more devices connect to the Internet, a new addressing format called IPv6 has emerged. This version utilizes a 128-bit number, allowing for a significantly larger range of possible addresses. Each packet of data specifies both the source IP address (the address from which it originated) and the destination IP address (the address it intends to reach).

- **Domain Names**: These are human-readable names used as an alternative to IP addresses. Domain names simplify the process of identifying and accessing resources on the Internet by providing an easier way for users to connect to websites and services.

- **Protocols**: A protocol is a predefined method by which a user communicates with a service. This "user" could be a person or, more commonly, a computer program, such as a web browser. Protocols are often text-based and outline the rules for interaction between the client and server. For instance, HTTP is a protocol used on the web. Common protocols for which firewall filters can be configured include:

```
    IP (Internet Protocol) - The primary delivery system for transmitting information over the Internet.
    TCP (Transmission Control Protocol) - Utilized to segment and reconstruct data that travels over the Internet.
    HTTP (Hyper Text Transfer Protocol) - Used for transferring web pages.
    FTP (File Transfer Protocol) - Used for uploading and downloading files.
    UDP (User Datagram Protocol) - Designed for transmitting data that does not require acknowledgment, such as streaming audio and video.
    ICMP (Internet Control Message Protocol) - Utilized by routers to exchange information with one another.
    SMTP (Simple Mail Transport Protocol) - Used for sending text-based information, such as emails.
    SNMP (Simple Network Management Protocol) - Used for collecting system information from remote computers.
    Telnet - Allows users to execute commands on a remote computer.
```

- **Ports**: Server machines make their services accessible to the Internet through numbered ports, with each port corresponding to a specific service. For instance, a server running both a web (HTTP) server and an FTP server would typically have the web server available on port 80 and the FTP server on port 21. Organizations may restrict access to port 21 on all machines except for one within the company. Ports serve to identify the purpose of a packet and direct it to the appropriate process. Although there are over 65,000 available ports, the majority remain unused on a daily basis. Certain services, such as HTTP for web browsers, have informal standard ports; while these can be modified, adhering to default ports simplifies user connections. Port numbers are typically appended to IP addresses and separated by a colon. For example, a packet destined for the IP address 230.105.4.32 and port 80 would have a destination address of 230.105.4.32:80.
 
- **Specific Words and Phrases**: This filter can include any set of terms. The firewall scans each packet for an exact match of the specified text. For example, one could configure the firewall to block any packet containing the phrase "X-rated." It is crucial that the match is exact; thus, the filter would not capture variations like "X rated" (without the hyphen). However, multiple words, phrases, and their variations can be included as needed.

- **Network Adapter**: A network adapter is a component of a computer's internal hardware that facilitates communication over a network with other devices. It enables a computer to connect to another computer, server, or networking device over a Local Area Network (LAN). Network adapters can be utilized in both wired and wireless networks.

## 802.1Q
802.1Q is an IEEE standard for frame tagging used in VLAN (Virtual Local Area Network) configurations. This standard is essential when creating a trunk link between a Cisco switch and a switch from another vendor, as it ensures interoperability. In 802.1Q, the trunking device inserts a 4-byte tag into the original Ethernet frame and recalculates the Frame Check Sequence (FCS) before sending the frame across the trunk link. Upon receiving the frame, the tag is removed, and the frame is forwarded to the designated VLAN.

## Subnet Mask

In IP addressing, the notation following the slash ("/") is a shorthand representation of a subnet mask, known as CIDR (Classless Inter-Domain Routing) notation, or the prefix length. The number after the slash indicates the number of consecutive 1's in the subnet mask. For example, the address 192.168.10.0/24 corresponds to the network 192.168.10.0 with a subnet mask of 255.255.255.0. In binary, 255.255.255.0 is represented as 24 consecutive 1's: 11111111.11111111.11111111.00000000.

Another example is 10.0.0.0/8, where the 8 consecutive 1's in the subnet mask correspond to 255.0.0.0, represented in binary as 11111111.00000000.00000000.00000000.


### IBM Documentation

- [Firewall rule language](https://www.ibm.com/support/knowledgecenter/en/SSB2MG_4.6.0/com.ibm.ips.doc/concepts/firewall_rules_language.htm)

- [Firewall rule syntax](https://www.ibm.com/support/knowledgecenter/SSB2MG_4.6.0/com.ibm.ips.doc/references/firewall_rule_syntax.htm)

- [Firewall rule examples](https://www.ibm.com/support/knowledgecenter/SSB2MG_4.6.0/com.ibm.ips.doc/references/firewall_rule_examples.htm)