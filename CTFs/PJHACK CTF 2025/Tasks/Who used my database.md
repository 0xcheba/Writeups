# Who used my database — Writeup

**Category:** *forensics*

## Description

Dwarf was making a server for books that he liked he knew it was poorly secured but he didn't thought that it is a problem. Yesterday he created a database and added to it his new favorite series of books. Today he found out that this database does not exist anymore. Luckily he have wireshark running on server, so now he asked you to help find what the attacker might have done and gathered. flag = one of faser packets + mac of dwarf + lastly added book.

## Solution

I was given a `.pcapng` file with captured network traffic. There was a lot of irrelevant traffic. I filtered out **ARP**, **ICMPv6**, and **DHCP** using the filter: `!arp && !icmpv6 && !dhcp`.
Next, I started to analyze packets starting from the end of dump. I quickly noticed that **HTTP POST** requests were unencrypted and I could read packet's content:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/database1.png" alt="Contents of the last packet"/>
</p>

Since encrypted traffic (HTTPS over TCP) would not help much here, I continued ignoring such packets.
As mentioned in the description, the flag consists of three parts: information from fuzzer, dwarf's (database owner) MAC address and the name of last added book.
I started looking for this information from the end of file and found the third part of the flag:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/database2.png" alt="The third part"/>
</p>

Next, I found a **GET** request where the attacker tried to access a suspicious-named directory. The directory name appeared to be the first part of the flag:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/database3.png" alt="The first part"/>
</p>

The `%7B` is an URL encoded "{" character.
The last part is the second part. To get the MAC address first I needed to find the dwarf's IP address. On the screenshot above there is a packet sent from the intruder's host to database server. Using the filter `ip.addr != 192.168.10.103 && !dhcp && !arp && !icmpv6`, I isolated traffic not originating from from the attacker. From this I found dwarf's IP address:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/database4.png" alt="dwarf's packets"/>
</p>

The dwarf's IP is `192.168.10.102`.
Then I located a packet sent from dwarf's IP and read the source MAC address:

<p align="center">
<img src="../../resources/PJHACK CTF 2025/database5.png" alt="The second part"/>
</p>

I combined three parts into the final flag:
`PJATK{3b4a1b8b6a08:00:27:08:35:95823e4c56d353}`