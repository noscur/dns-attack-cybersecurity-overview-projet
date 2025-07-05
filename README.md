# Cybersecurity Project - Group 11 : Discovery and Implementation of some DNS attacks

- [Cybersecurity Project - Group 11 : Discovery and Implementation of some DNS attacks](#cybersecurity-project---group-11--discovery-and-implementation-of-some-dns-attacks)
  - [Problem statement](#problem-statement)
  - [Reference](#reference)
    - [DNS Tunneling Attack](#dns-tunneling-attack)
    - [DNS Poisoning](#dns-poisoning)
    - [DNS Amplification](#dns-amplification)
  - [Documentation of project](#documentation-of-project)
    - [DNS Tunneling Attack](#dns-tunneling-attack-1)
      - [Context/Assumption](#contextassumption)
      - [How it works](#how-it-works)
        - [Flow overview](#flow-overview)
    - [DNS Poisoning](#dns-poisoning-1)
      - [Introduction of DNS Spoofing Attack](#introduction-of-dns-spoofing-attack)
      - [Context/Assumption](#contextassumption-1)
      - [Files and Usage](#files-and-usage)
      - [Configuration file](#configuration-file)
      - [How it works](#how-it-works-1)
        - [Spoofer explained](#spoofer-explained)
        - [InputDNSRequestProcessing explained](#inputdnsrequestprocessing-explained)
        - [InputDNSResponseProcessing explained](#inputdnsresponseprocessing-explained)
        - [Flow of the attack](#flow-of-the-attack)
      - [Usage of this attack](#usage-of-this-attack)
    - [DNS Amplification](#dns-amplification)
      - [Overview](#overview)
      - [Context/Assumption](#contextassumption-2)
      - [How it works](#how-it-works-2)
      - [Amplification attack flow description](#amplification-attack-flow-description)
     
  - [Documentation on testing the project](#documentation-on-testing-the-project)
    - [Installation](#installation)
    - [DNS Tunneling Attack](#dns-tunneling-attack-2)
    - [DNS Poisoning](#dns-poisoning-2)
      - [Network Architecture](#network-architecture)
      - [Requirements on the attacker system](#requirements-on-the-attacker-system)
      - [Requirements on the target system](#requirements-on-the-target-system)
    - [DNS Amplification](#dns-amplification-2)
  - [Own contribution](#own-contribution)
    - [John DOE](#john-doe)
    - [Nathan MOUSSU](#nathan-moussu)
    - [Bob DOE](#bob-doe)
    - [James Doe](#james-doe)

## Problem statement

The purpose of our project is to explore some DNS attacks to clearly understand them, and thus expose vulnerabilities that must be monitored. The DNS is one of the cornerstones of the Internet. Almost every machine uses a DNS server/resolver, even in local infrastructure or in a deep network. The failure of the DNS will lead to quiet unusable entire networks. It can affect people all over the world, as it happened in [2016 with the DDoS attack against DYN](https://en.wikipedia.org/wiki/DDoS_attacks_on_Dyn). DNS is complex, with a specific hierarchy of servers. Many servers are involved in the resolution of one query, and those servers can be held by hackers, as anyone is able to buy and use a domain on the internet for only a few dollars. That is why it is important to identify how a hacker can use the DNS to perform attacks.

## Reference

### DNS Tunneling Attack

- [What is DNS tunneling](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling) Paloalto, "What is DNS tunneling", Accessed 16th Sep. 2024.

- [DNS Tunneling Attack: Definition, Examples, and Prevention](https://hop.extrahop.com/resources/attacks/dns-tunneling/) Extrahop, "DNS Tunneling Attack: Definition, Examples, and Prevention", Accessed 16th Sep. 2024.

### DNS Poisoning

- [Cloudflare Learning](https://www.cloudflare.com/learning/dns/dns-cache-poisoning/) Cloudflare. "DNS Cache Poisoning." Cloudflare Learning, Accessed  15th Sep. 2024.

- [Fortinet Cyber Glossary DNS Poisoning](https://www.fortinet.com/resources/cyberglossary/dns-poisoning) Fortinet "DNS Poisoning" Fortinet Cyber Glossary,  Accessed 17th Sep. 2024.

- [Scapy Documentation](https://scapy.readthedocs.io/) Scapy Project. "Scapy - Python-based Interactive Network Exploration Tool" Scapy Documentation, Accessed multiples time since 25th Sep. 2024.

- [Iptables Manual](https://linux.die.net/man/8/iptables) Linux Die. "iptables manual" Linux Die iptables Manual, Accessed 6th Oct. 2024.

### DNS Amplification

- [DNS amplification DDoS attack](https://www.cloudflare.com/en-gb/learning/ddos/dns-amplification-ddos-attack/) Cloudflare. "DNS amplification attack". Accessed 19th Sep. 2024
- M. Hickey, Hands on Hacking: Chapter 5, Hoboken NJ, USA: John Wiley & Sons, Inc. 2020
- [Scapy tutorial](https://www.youtube.com/watch?v=EuTAmtMGdNU&t=61s) as well as the rest in his series. danscourses.com, "Scapy and Python Part 1 - Install, Run, Sniff", Accessed 5th Oct. 2024. 

## Documentation of project

### DNS Tunneling Attack

In a few words, this attack is very simple. A hacker uses the DNS protocol to exfiltrate data from a machine. The data is embedded and hidden in the queries of the DNS protocol. Thus, a hacker can bypass some firewall rules.

#### Context/Assumption

- We suppose that the hacker can execute, or at least upload and start, the malware on the targetted host, regardless of the way he does so.
- We will also assume that the firewall in front of the target is quite restrictive, and that traditional reverse shell for example can't be used. Thus, we will just suppose that the target has access to a DNS resolver, and that this resolver can resolve any domain. In other words, the target is able to send UDP packet to the port 53 of its default resolver, and this resolver is able to answer the query.

#### How it works

The hacker has a DNS server that he controls. For us, this is what we are going to call the [malware server](./dns-tunneling-attack/server/main.py).

This one is responsible for a domain (or a zone). In our case, it will be the zone for the subdomain `dnstunnelingattack.project.local`.

So, in the DNS server of our domain (`project.local`), we delegate the zone `dnstunnelingattack.project.local` to our malware server.

So, when a machine from all over the world wants to resolve information about this zone, the queries will be directed to the DNS server of our domain, that will in turn redirect the queries to our malware server.

This said, when our target asks its resolver about queries concerning the zone `dnstunnelingattack.project.local`, it will reach our malware server.

***Disclaimer: As our domain and infrastructure are local, and because of certain DNS server behaviors that would have forced us to develop a much more complex program to meet its requirements, which concern the network and not cybersecurity, we decided that our client-side malware would contact the malware server responsible for the `dnstunnelingattack.project.local` zone directly, and therefore not go through our domain's DNS server (which is the classic path for DNS resolution). But the attack remains valid in all cases, as soon as the target can contact a resolver that can resolve any domain. In what follows, we continue to explain the attack as if we were in real-life conditions.***

Now, we just have to design the way we will hide data into the DNS queries.

We can act both on the server side, and also on the client side.

Here we describe how we have implemented our basic reverse shell via DNS tunneling, but the principle can be used to do many things, like exfiltrating files, executed predefined scripts, ...

On the server side, we have added what we can call an "admin interface" that the hacker can connect to and execute commands on the target.

To see how I have implemented my reverse shell through DNS queries, check [my own contribution](#john-doe)

##### Flow overview

Here I give an example step-by-step of the flow of this attack, check [my own contribution](#john-doe) for details:
- the hacker starts the malware on the target
- this target sends a "hello" query to the malware server:
  - it is just a query asking for the IPv4 of the hostname `dnstunneling.poject.local`
- the server identifies this "hello" query, and thus detects that a new victim is now connected. He responds and asks to execute the command `hostname` to identify the hostname of the target. Again, two response elements in the DNS response:
  - `dnstunneling.poject.local` is a CNAME of `aG9zdG5hbWU=.dnstunneling.poject.local` (base64("hostname") = "aG9zdG5hbWU=")
  - `aG9zdG5hbWU=.dnstunneling.poject.local` has for IPv4 `1.2.3.4`
- the target gets the response, decodes the base64 string, executes the command and forms a query with the response: `<base64 of the output of the hostname command>.dnstunneling.project.local`. The target sends it back to the server.
- the server decodes the query and obtains the hostname. He now asks for the user that is executing the malware on the target.
- the client responds with the user
- the server gets the username, and now the hacker can send arbitrary commands using the same principle
... and so on...

### DNS Poisoning

#### Introduction of DNS Spoofing Attack

The DNS Spoofing attack aims to manipulate DNS Records, making them seem valid to the sender of the DNS Request. It is generally used to modifiy a few selected entries, redirecting to a server that the attacker owns. The attacker's server can copy the login page corresponding to the spoofed name entry, and then steals things like credentials. They can stay some time in the cache, producing malicious redirection of the request to the attacked resources during the validity of the entries.

#### Context/Assumption

- We suppose that the attacker (you) is on the same local network (LAN) as its target, can be wifi or ethernet.
- We suppose that the target and attacker (you) use the same DNS Server served by DHCP.

#### Files and Usage

This attack needs these files in the same directory to work:
- Spoofer.py
- InputDNSRequestProcessing.py
- InputDNSResponseProcessing.py
- main.py
- changed_entries.conf

#### Configuration file

To configure which entries you want to redirect to which IP in the configuration file (`changed_entries.conf`), use this format, one per line:
`<name>:<IP Address>`

So that you can have this for example:

```
www.noscur.fr.:192.168.0.130
www.google.fr.:192.168.0.130
```

Don't forget the root point at the end if not it won't works.

```sh
sudo python3 main.py <target_ip> <network_interface>
```

#### How it works


This DNS Spoofing attack is using three main components (design as Class and use as objects in python):

Spoofer
InputDNSRequestProcessing
InputDNSResponseProcessing

##### Spoofer explained

- Inherits from Thread class
- Sets up a man-in-the-middle attack between the gateway and the targeted system
- Configures packet forwarding : ```sudo sysctl -w net.ipv4.ip_forward=1```
- Accepts forwarding of packets in the firewall : ```sudo iptables -A FORWARD -i <interface> -o <interface> -j ACCEPT```
- Drops packet forwarding from the target to the DNS server(s) : ```sudo iptables -I FORWARD 1 -p udp --dport 53 -d <dns_1_ip> -s <target_ip> -j DROP```
- Allows the attacker to read all packets between the target and the gateway and filters some packet with firewall

##### InputDNSRequestProcessing explained


- Sniffs DNS packets coming from the target system
- Checks if the DNS query matches entries in the configuration file explained before
- If matched, crafts a DNS response with the associated modified IP address
- If not matched, attempts to modify the original packet to use the attacker's IP address
- Allows the attack to selectively modify DNS responses based on predefined rules

##### InputDNSResponseProcessing explained


- Sniffs DNS responses from DNS servers
- Receives the response to the modified DNS query from InputDNSRequestProcessing
- Copies the received packet
- Modifies the destination IP to send it back to the target
- Allows the attack to forward modified DNS responses back to the victim

##### Flow of the attack


1. The Spoofer sets up the man-in-the-middle position.
2. When the target makes a DNS query, InputDNSRequestProcessing process it and the firewall keep it to go to the DNS Server.
3. If the query matches a rule in the config file, a modified response is crafted and sent back and that's it for this request. If not matching, the original packet is modified to use the attacker's IP and send it to the DNS server.
4. The DNS server responds to the attacker. (only if not matching in step 3 we have this step and next ones)
5. InputDNSResponseProcessing receives this response.
6. It copies the packet and changes the destination IP from the attacker's IP to the target one.
7. The modified response is sent back to the victim.


#### Usage of this attack

This attack can be use for several usages:
- Voiding requests to a services that we don't want our victim to use
- Redirecting the victim to a server we own to steal things like facebook credentials when he tries to access facebook.com ...

The probability of stealing credentials is higher because the website won't be suspicious since the link is the good one, during the attack the victim can browse like always so it allows the attacker to wait for the victim to go to one of the configured targeted name.

### DNS Amplification

#### Overview

A DNS amplification attack is a type of Distributed Denial of Service (DDoS) attack that exploits vulnerable DNS servers to overwhelm a target system with traffic. By sending a small request with a spoofed source IP (the victim's IP), an attacker can trigger a significantly larger response from the DNS server, effectively bombarding the target and causing service disruption.

#### Context/Assumption

In this scenario, we assume that the attacker managed to infect with malware a group of hosts which will be referred to as ‘bots’ or ‘botnets’. The attacker has also control over a server that provides instructions to our group of botnets on which target to attack and how to execute the attack. The attack relies on the availability of a DNS resolver within this network that respond to requests with the victim's IP address as the source. For our project we operate within a closed internal network.

#### How It Works

Server Setup: The attacker sets up a server that listens for incoming connections from the attacker himself. This server receives input for the target's IP, the resolver's IP, and the DNS query, and sends this information to the bots. 
- File: `server.py` handles incoming connections and manages the bots.
- File: `main.py` initializes the server.

Botnet Simulation: Multiple instances of the botnet are created, with each instance capable of sending DNS queries.
- File: `botnet.py` simulates the behaviour of the botnets, generating DNS requests based on commands received from the server. Each bot sends 1000 DNS requests to the specified resolver IP for a particular query.

Docker Implementation: The attack is orchestrated using Docker, creating 40 separate instances of the botnet (one per Docker container) and another container for the server.

#### Amplification attack flow description

1.	The attacker starts the server, which once is running waits for incoming connections from the attacker.
2.	By using a secondary thread created when the server is started, the server listens for each botnet instance to send information to the server about the socket (IP address + port number) on the botnet side that the server should use to transmit the data required for the attack to each bot. 
3.	The server upon receiving the target IP, resolver IP, and the DNS query from the attacker, sends instructions to each bot to generate a DNS request to the resolver.
4.	The DNS requests are crafted to elicit large responses, effectively amplifying the traffic sent to the target. The bots send multiple queries to increase the impact.


## Documentation on testing the project

### Installation

We use docker to create virtual containers and setup an isolated infrastructure for the purpose of our project.

All you have to do is:
- [install docker](https://docs.docker.com/engine/install/). If you are using Linux, you can use [this script](https://get.docker.com/) to install docker with just one line.
- run `make` to check if docker is correctly installed and create a virtual network for our project

Now, you can start the infrastructure with `docker compose up`. Add `-d` if you want to detach your terminal.

You should now be able to query our DNS server, with `dig project.local @172.23.0.53`. The port `5053` of your machine is bound on the port `53` of the container, so you can also perform `dig project.local @localhost -p 5053`, but you can also add the DNS server in your system and delete the `@` mentioned in the previous command.

Notes : 
- We use static IPs and not the embedded docker DNS, that is why we need to first create a network with a specific IP range. If you already have one on your computer using this range, or if you are already using this range, you have to change it, and also change all mentions of IPs in the configuration files.
- If you encounter problems while connecting to a container, or the connection between containers, check if your firewall is not blocking it.

### DNS Tunneling Attack

Once the containers are running, you can open (at least) two terminals:
- one for connection with the admin interface. You just have to open a TCP connection to port 3000 of your machine, that is bound to the container. (you can perform `nc localhost 3000`)
***Warning: you must close the admin interface with the command `exit`, else the server will crash and you will have to restart it.***
- one for your victim. Again, as our infrastructure is local, the victim must be able to reach any container of the range in order for the attack to work. You can start the malware on your own machine or on another container if you want. To start the malware, just run `python3 malware-client.py`

Now, on the admin interface, you can perform the following commands:
- `list`, to list the connected victims
- `exit`, to close the admin interface (not the server)
- `connect <IP>`, to start a reverse shell with one of the victims that are connected to the server

### DNS Poisoning

#### Network Architecture

LAN Network with at least these 3 systems:
- Router / Gateway to internet
- Attacker system
- Target system

DNS Server(s) can be the same IP as the gateway, another IP in the LAN network or a public IP it doesn't matter as long as DNS requests will go through the gateway.

We tested it by making a hotspot with a phone and connecting on it with 2 computers, one for the attacker and one for the target. For test purposes, we installed nginx locally on the attacker system to redirect the victim on it while using the modified name entry.

#### Requirements on the attacker system

- `sudo` access to execute the python program
- python3
- `iptables`package`
- `/etc/resolv.conf`` with DNS Server fetch from DHCP
- Python Third Part Libraries : scapy, netifaces
- `iproute2` package for `ip a` and `ip route`
- `sysctl` command

```sh
pip install scapy
pip install netifaces
```

Since the program needs to be launch with sudo, the python library needs to be installed as root or in a python virtual environment.

#### Requirements on the target system

- Usage of DNS servers provided by DHCP (Need to disable private DNS or static set DNS)

### DNS Amplification

If you ran `docker compose up`, you have started 40 botnets and the central server for this attack.

You now have to open two terminals:
- one where you are going to start a new container in the same network. It will be the victim. Run `docker run -it --rm --network cyberproject-network alpine:latest /bin/sh` and start a ping to an IP `ping 8.8.8.8`.
- on the second one, you will have to limit the bandwidth of the victim to limit the number of botnets to use. For this, identify the id of the victims with `docker ps`, and run `docker exec <victim_id> ip addr show`. Now, identify the interface name of the container (not the loopback interface), it should be something like `eth0@if66`, where `if66` is the ID of the interface. Also note the IP of the container. Now, run this command: `sudo tc qdisc add dev <interface_ID> root tbf rate 1mbit burst 32kbit latency 400ms`. Now, you can start the attack using for example `nc localhost 3002`. You can now provide the IP of the victim for the target, `172.23.0.53` as the IP of the DNS server (the local bind server) and `project.local` as the domain name to query.

You will see that the response time of the ping on the victim will normally increase a lot (x100).

## Own contribution

### John Doe

I am passionate about networking as well as cybersecurity, so working on DNS attacks was the perfect opportunity for me to bring these two themes together. With Nathan's help, I was able to explain the basics of network needs for the project to the other members of the group.

After quickly deploying a local working environment, I focused on the DNS tunneling attack, that is for me very interesting to bypass firewalls. So I decided to implement a reverse shell with this attack. I thus designed a way to embed data in DNS queries, and the idea remains valid for all kinds of data extraction, not just for reverse shell. I just wanted to put a little disclaimer: maybe there already exists something similar on the internet, but I have quickly searched what the purposes of this attack were and used my knowledge to build my own tool and protocol. I detail here the idea, and after that I say a little word about detection of this attack, and how to go further.

- Communication from the victim to the server: When the client receives a command, he executes it and encodes the output (error or not) using base64 (see next point to understand how it receives the command). Then, it sends a DNS query to its defaut resolver to resolve the IPv4 (query type `A`, for an IPv4 entry) of the next hostname: `<base64 of the command's output>.dnstunneling.project.local`. As the DNS protocol requires a limit of characters in the items of the hostname, I can split it into blocks: `<base64 output block1>.<base64 output block2>.dnstunneling.project.local`. Again, as the domain name of the query is `project.local`, the query will be sent to our DNS server, that will send it to our malware server because it concerns the zone `dnstunneling.project.local`. Our malware server just has to reform and decode the query to get the output of the command it asked to execute.
- Communication from the server to the victim: Due to the firewall, the server is only able to respond to a query asked by the victim. So, when he gets a query, the hacker can send a command in the response to this query. To do so, I have designed a little "trick" to get rid of the limited size of an IPv4 or IPv6 address. Indeed, I wanted to be able to execute any query on the target, regardless of the size of this command. So, I decided to respond to a query by using a CNAME entry (it is basically an alias of an entry). So, as for the other sense of communication, I encode the command in one (or many) base64 string, and I add it to our zone name: `<base64 of the command>.dnstunneling.project.local`. I then add another response, that is a random IPv4 where this hostname points to (I can have multiple responses in a single DNS response packet). Then, the malware running on the target can simply reform and decode the command that the server wants it to execute. Here is an example of such a response: if the original query is `aG9zdG5hbWU=.dnstunneling.poject.local`, the response contains two things :
  - a first response saying that `aG9zdG5hbWU=.dnstunneling.poject.local` is a CNAME of `<base64 of the command 'aG9zdG5hbWU='='hostname'>.dnstunneling.project.local`
  - a second that is a random IPv4 corresponding to `<base64 of the command 'aG9zdG5hbWU='='hostname'>.dnstunneling.project.local` (I need it because the DNS protocol is designed the way that the resolver wants an IP when he gets a CNAME entry as response)

Now a little word about detection. If we do not take into account the detection of the malware execution on the victim, I see right now only one kind of defensive measure that can detect the tunneling attack: DNS packet scanning, for example with IDS/IPS.

This kind of stuff can use AI to detect unusual behavior or requests, or something that is probably not a human legitimate action. But it requires to scan all the DNS packets on the network.

The way I have designed the exfiltration of data, it is very easy to detect it, because of the base64 encoding in the queries. But I have thought of two ways to upgrade this (I assume here that the domain is legitimate, and not something strange like `dnsattack.se`):
- encrypt the data using, for example, a key stored in the malware. This way, IDS/IPS will probably detect it, but can't explicitly identify what is going on
- use a map between the most commonly used subdomains and the base64 encoding. If we use this kind of [list](https://github.com/rbsec/dnscan/blob/master/subdomains-10000.txt), we can map each character of the base64 encoding protocol to a well-kown subdomain, and send them one by one, with a delay between the queries. This way, it could potentially be a real human navigating to a website, discovering subdomains. To my opinion, the scanners will have more difficulty detecting the attack, especially if the queries are delayed by many seconds, or at least IPS/IDS would not be able to assert with the same probability that it is an attack. But his kind of trick requires much time.

We could also use additional DNS packet information, but they would potentially be overwritten by the resolver, depending on its configuration, and the problem remains the same, how to hide data ?

### Nathan MOUSSU
As someone interested in networking, I delved into various network-related topics, focusing particularly on DNS. During my research, I discovered three significant DNS attacks: Amplification Attack, DNS Poisoning, and Zone Transfer Attack.
I collaborated with John to explain DNS protocol, DNS Server, and Resolver concepts to two group members who lacked prior knowledge in this area. This initiative aimed to create a foundation for understanding DNS operations within our team.
To assist other group members in starting their exploration of DNS manipulation, I created a code example demonstrating how to send a simple DNS Request using the python library scapy. This example allowed team members to manipulate packets and gain hands-on experience with DNS operations.
As part of my task, I focused on implementing DNS poisoning. My approach involved researching several methods to achieve this:
1.	Birthday Paradox (brute force method)
2.	Man-in-the-middle technique
3.	Directly modifying server configurations (as practiced by some countries to restrict access to certain sites)

Initially, I attempted to use the Birthday Paradox method, but my implementation proved too slow to effectively poison even one entry within tens of tries.
Given the limitations of the Birthday Paradox method, I shifted my focus to the Man-in-the-middle approach. Leveraging my understanding of ARP, I discovered that spamming ARP packets with my MAC Address set to <spoofed_ip> towards a victim's MAC and IP would cause poisoning of the victim's ARP table. This allowed me to intercept traffic between the gateway and target with repeating the operation for both target and gateway.
To decrease the probability of the user thinking something isn’t right, I enabled IP packet forwarding and added a firewall rule to forward those packets. However, reading queries and answering before DNS servers proved too slow most of the time.
To overcome the speed limitations, I implemented the following optimizations:
1.	Added a firewall rule to drop packets in the forward chain originating from the target IP to the DHCP-configured DNS servers.
2.	Modified the approach to send DNS Requests to the DNS Server, modifying only the MAC source address and IP source address with attacker values.
3.	Created a program to listen for DNS responses coming with the attacker IP as the destination and then modified the MAC destination address and IP with the target IP so that the target can access all other services or servers behind the untargeted names.

Finally, I developed a configuration file to set up entries with names and corresponding modified IP addresses that will be the poisoned entries. To test the redirection on another server, I installed nginx locally.

### Bob Doe

In our group, the difference in experience and knowledge levels among members has significantly shaped our learning and collaboration process. Our more experienced colleagues, Nathan and John, have shared their extensive knowledge of IT and networking with James and me. Their guidance has helped us to learn how DNS works in general and the specific attacks we focused on: DNS tunnelling, DNS poisoning and especially DNS amplification.

Given the significant knowledge gap, I invested much of my due time (40 hours) into studying not just the attacks themselves, but also the structure and functionality of the DNS system, including its components and how DNS entries are managed. A very rich and powerful source was Chapter 5: The Domain Name System from the publication "Hands on Hacking: Become an expert at next gen penetration testing and purple teaming" by Matthew Hickey with Jennifer Arcuri. This foundational knowledge was crucial for effectively understanding and executing our project objectives. 

In regard to the development of the DNS amplification attack, James and I have collaborated in order to develop it. Through this process, I've gained hands-on experience in executing this attack within a controlled internal network environment, where with the help of john doe regarding Dockers (since none of us had prior knowledge about creating containers) we have designed a botnet and implemented 40 instances of Docker containers that simulated the botnet network behaviour, sending numerous DNS queries to a vulnerable DNS resolver with a spoofed source IP—specifically, the victim's IP address. This technique allowed us to effectively overwhelm our objective it with “malicious” traffic disabling/decreasing its operational capability.

Additionally, James and I took our part in creating comprehensive documentation related to our DNS amplification attack, which we uploaded on GitHub. This documentation serves to detail our methodology, findings, and insights, contributing to the overall understanding of DNS attacks within our team.

### James Doe
This project has been a great place for learning. As a physics engineering student with no prior experience with networks and even less with DNS, this has been a fantastic opportunity to learn about these fundamental aspects of cybersecurity. A lot of time went into reading, watching, and listening about the basics of network engineering and especially DNS. To be able to comfortably talk about the core concepts present in networks and the DNS is for me a great achievement.

I have, together with Bob, been responsible for developing a DNS Amplification Attack. We both have similar backgrounds so we felt we could really see the same difficulties and support eachother throughout the project. A DNS Amplification Attack in general relies on the built in functionality and existance of open resolvers and IP spoofing to give a target a huge amount of DNS answers which it did not ask for, hopefully giving so many that it exceeds the targets bandwidth and makes in inaccessible for others, or otherwise unable to perform its regular functions. In other words, it's a DoS attack. For greatest efficiency a botnet would be used, therefore able to send many more queries to DNS servers without being restricted by a specific device's network card. Therefore we have modeled it as a DDoS attack. Our infrastructure is as follows. The core part of the attack is a server which we created using the socket and thread libraries in python. This server can do three things. Firstly, the hacker can connect to it and send instructions for the DNS Amplification Attack. These instructions consist of the targets IP, which DNS server to send the packets to, and which domain name to query. The second thing the server can do is collect the IP and port of the devices installed with the malware and lastly send packets to the botnet. These bots are assumed to have been compromised and have had a malware installed with them, as well as us gaining root privileges to install and run a library called Scapy which is necessary to create DNS packets with spoofed IPs which is the essence of the attack. The server will relay the information to the botnet which will in turn execute the attack.

I want to take the opportunity to express my gratitude to Nathan and John, who have been very patient with my lack of knowledge and been great support for me when I have had had a hard time with a part of the project. Just to make an example Nathan realized that the reason I was having so much trouble with getting my IP spoofing to work was because of the double NAT that occured. Firstly when the packet left WSL to windows, and of course later when the packet left the router. I could have spent an entirety on this single issue alone and most likely never have found the solution.

In the same way I want to highlight the enourmous assitance me and Bob recieved when implementing the docker botnet (and everything to do with docker in generel). There were many small issues that arose when entering our code into docker, and in each case John had the knowledge to either solve it immeadiatly, or to find the solution with speed. It was truly a luxory to have Nathan and john doe on our team.
