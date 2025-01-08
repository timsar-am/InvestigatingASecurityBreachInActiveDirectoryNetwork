## PROJECT NAME

Investigating a Security Breach in Active Directory Network

## Objective

Scenario: 

As a SOC analyst, you aim to investigate a security breach in an Active Directory network using Splunk SIEM (Security information and event management) solution to uncover the attacker's steps and techniques while creating a timeline of their activities. The investigation begins with network enumeration to identify potential vulnerabilities. Using a specialized privilege escalation tool, the attacker exploited an unquoted service path vulnerability in a specific process.

Once the attacker had elevated access, the attacker launched a DCsync attack to extract sensitive data from the Active Directory domain controller, compromising user accounts. The attacker employed evasion techniques to avoid detection and utilized pass-the-hash (pth) attack to gain unauthorized access to user accounts. Pivoting through the network, the attacker explored different systems and established persistence.

## Skills

- Threat Hunting

## Tactics

Reconnaissance, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Command and Control

### Tools Used

- Splunk

## Steps

My first task is to determine the name of the compromises account. First I look up windows event ID 4625 (failed login) and then 4624 (successful login) We see here 29 failed login attempts under CLIENT02

![image](https://github.com/user-attachments/assets/39ff9ad3-1ae5-4c68-969e-de1ff9c46ca5)

I add the field subjectUserSID. Top 2 fields are irrelevant for our task. Compromised account is Abdullah-work\Helpdesk. The next task is to determine the compromised machine which I did in the previous query.  CLIENT02

![image](https://github.com/user-attachments/assets/39551c3f-78c1-4d2c-a0d2-c9814f41f956)

Now that we know what account and machine was compromised, my next task is to determine the tool the attacker used to enumerate the environment. I do a quick search on what tools are typically used for reconnaissance in Active Directory. Powerview and Bloodhound came up.  This is typically done in the command line so I do a simple query and get the answer

![image](https://github.com/user-attachments/assets/380f7ee8-cf9b-4364-8717-588c82927b37)

The attacker used Unquoted Service Path to escalate privileges. My task is to determine the name of the vulnerable service.  I had to look this up. This would be something that would show up in vulnerability scan. Basically a program or service is installed, the location of that app or service in the windows registry contains a space. Attacker can insert an executable file into the affected path.

Now that I know this I know what to look for. Attacker most likely created a service.  I run a simple query

![image](https://github.com/user-attachments/assets/5e2142c3-b32c-4a86-a0dd-f4a7fb54d3ed)

![image](https://github.com/user-attachments/assets/8a9fb1b1-16c0-4051-b001-24088eecf7fa)

I find the answer is Automate-Basic-Monitoring.exe 

The next task is to find the SHA256 of the executable that escalates the attacker privileges. We know the executable from the previous task. I run the query:

![image](https://github.com/user-attachments/assets/cc8a013e-4146-41d7-9f13-976d3cd22555)

I find the answer. SHA256 = 8ACC5D98CFFE8FE7D85DE218971B18D49166922D079676729055939463555BD2

My next task is to determine what time the attacker downloaded fun.exe
I do a simple query and look for the earliest event. You can also | table _time but I like to see the entire event

![image](https://github.com/user-attachments/assets/6a17d4a5-b4a2-415a-a6db-d182eac94c37)

Answer is 2023-05-10 05:08:57

My next task is to determine the command line used to launch the DCSync attack. I had to look this up as well.
Basically Dsync attack is when the attacker simulates the actions of a Domain Controller. They can retrieve password data via domain replication. If a Dsync attack has occurred. It means the attacker is in the late stages of the cyber kill chain as major permissions are required. This attack is a command in the tool Mimikatz. 

Since this is a well known tool. I can do a simple search for any traces.

![image](https://github.com/user-attachments/assets/8b6a13f1-d619-4efc-8a8c-8b5c14fcb27b)

Under the CommandLine Field I find the answer: "C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"

![image](https://github.com/user-attachments/assets/c7612e08-3e45-4b1b-992b-e7bcf1b5ef15)

My next task is to determine the original name of fun.exe
I run a simple search and add the field OriginalFileName and I get the answer: Mimikatz.exe

![image](https://github.com/user-attachments/assets/ea9d44b4-83c7-4490-bce1-7d469c8d549c)

![image](https://github.com/user-attachments/assets/835a9308-7c2f-4c1a-bc0e-3c67cf1d658e)

The attacker performed the Over-Pass-The-Hash technique. My next task is to find the AES256 hash of the account he attacked. 

Since this is in an active directory environment, the attacker would have gained AES keys using Mimikatz. I looked this up and it seems another way to pull the AES keys is to run the command sekurlsa::ekeys

I tried looking for any trace of that command without any luck. I then looked up event ID 4648 (logon using explicit credentials) and no luck there either. 

Next I tried to search for event ID 4768 (Kerberos authentication ticket requested)

![image](https://github.com/user-attachments/assets/0c0195c1-a21a-4089-9d98-71ef3a18d273)

To narrow down the search, I add the field TicketEncryptionType. 

![image](https://github.com/user-attachments/assets/ed1f2ff4-1cc5-4896-ae13-8a17d90ca614)

There are only two. I quickly look these up.

![image](https://github.com/user-attachments/assets/989eac1f-bd22-4bba-9b19-828bd534c910)

![image](https://github.com/user-attachments/assets/19c9ee80-b861-44fe-b173-bb436fb4037b)

I look at the lone event for 0x17. Looks like user Mohammed was the target. Now that I know the user I search AES256 that would have shown up in the command line.

![image](https://github.com/user-attachments/assets/8adb2e59-1877-4026-9e36-8228ef5f59ac)

I find the answer. AES256: facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

![image](https://github.com/user-attachments/assets/8b6ac710-a98d-47b2-844c-06c82a106863)

My next task is to determine what service the attacker abused to access the Client03 machine as Administrator.
He would have done this while still on Client02 so I look for any commands that mention Client03.

![image](https://github.com/user-attachments/assets/0ac0194f-4a26-4dca-bbe4-4aa240693fdb)

There are 20 events but only one contains any run commands.

![image](https://github.com/user-attachments/assets/b36d6c0e-ede3-4278-bb47-ab67ff633516)

I go to the event to investigate and find the answer. http/Client03

![image](https://github.com/user-attachments/assets/53ebb0ae-07a5-4ec6-b8d0-c0f2ae81881d)

Client03 machine spawned a new process when the attacker logged on remotely. My task is to find the process name.

I already know the time and date (5/10/2023 6:18:19:000 AM) of this part of the attack from the previous question. I filter for events after 05/10/2023. 177 events come up.

![image](https://github.com/user-attachments/assets/6af1cd48-ea9f-4226-94aa-ab63b8399b2d)

I add | table CommandLine _time so I can look for process that occurred right after 6:18:19AM

![image](https://github.com/user-attachments/assets/8d864e22-b626-4f42-9b10-2001b1559467)

I can see here the events that occurred right after attacker ran the service http/Client03. 

![image](https://github.com/user-attachments/assets/dc9327f9-0cf9-4d16-8619-a41d60bfbca5)

I like looking at the entire event so I go in to take a better look. Answer is wsmprovhost.exe

![image](https://github.com/user-attachments/assets/f1d9bffc-0217-4aea-98db-30d9913360de)

The attacker compromises the it-support account. I need to find out what the logon type was. 
From a previous question I know the attacker executed overpass-the-hash attack. While I was looking it up, I learned that this type of attack shows a log on type 9 in the logs. 

![image](https://github.com/user-attachments/assets/ed37c244-2c40-4830-8be4-da7e10d2628b)

Logon type 9 shows attacker logged on using same local identity but with different credentials. Attacker successfully logged on as HelpDesk. 

![image](https://github.com/user-attachments/assets/d9075588-5293-4888-bcb7-fc18a5e86b25)

My next task is to find out the ticket name the attacker generated to access the parent DC as Administrator.
I do a simple search and look in the command line. Answer is trust-test2.kirbi 

![image](https://github.com/user-attachments/assets/7c6b2ee2-ad6b-4064-a545-88453e7a6a8b)

![image](https://github.com/user-attachments/assets/dbd08077-e978-47a4-a971-8b72889e1433)

![image](https://github.com/user-attachments/assets/82c05cf9-f97b-410f-b6b3-91553dc90c86)





