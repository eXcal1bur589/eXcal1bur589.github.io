# Bank
Bank is a retired Hack The Box server with a Hack The Box difficulty rating of easy. Community ratings put it at a medium difficulty. The description of the box mentions SUID and web as possible methods of exploitation.

### Enumeration
The IP address listed for this host is 10.10.10.29. To start off, I will run a full TCP/UDP port scan on the target with nmap. The command for the TCP port scan is:

```
sudo nmap -sS -A -p- -T4 10.10.10.29 -oA results
```

And the command for the UDP scan is:

```
sudo nmap -sU --max-retries 0 10.10.10.29 -oA results-udp
```

Based on the output of the TCP scan, the following ports are open:

![[Pasted image 20210630093908.png]]

The UDP scan doesn't reveal any other interesting ports, but does seem to confirm the presence of a DNS server running on the target as well:

![[Pasted image 20210630094315.png]]

##### Hydra
While I look in to the web server and DNS server, I'll start an SSH brute force in the background (always be cracking!). I'll use hydra for this, with the username list being the SecLists top usernames shortlist and the password list being rockyou:

```
hydra -L /usr/share/wordlists/SecLists/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.29
```

##### 80 (Apache)
According to the nmap scan, we have an Apache 2.4.7 web server running on the target. It also reveals that the underlying host OS is likely to be Ubuntu. Browsing to the server, I'm greeted with a default Apache web page:

![[Pasted image 20210630100636.png]]

Usually when you find web servers with default pages still present, it's an indicator that the company has a poor security posture. Default web pages should be removed/disabled. 

##### Nikto
To find out more information about the web server, I'm going to run nikto against it with the following command:

```
nikto -h http://10.10.10.29
```

The results of nikto unfortunately didn't include any information that may lead to compromising the target:

![[Pasted image 20210630103530.png]]

##### Hosts File
In order to enumerate the web site more, a hosts file entry for bank.htb is required. Once a hosts file entry is present, visiting the web site presents a login page:

![[Pasted image 20210630143654.png]]

##### 53 (DNS)
Now that I have a domain name to use (bank.htb), I did a zone transfer to see if I could get any additional domains to enumerate:

```
dig @10.10.10.29 bank.htb -t AXFR +nocookie
```

The results don't reveal any other domains that can be accessed via the IP of this host:

![[Pasted image 20210701101215.png]]

##### Login Page
I tried some simple SQL injections to see if I could bypass the login page, but the web site doesn't appear to be vulnerable to it:

![[Pasted image 20210630144059.png]]

Examining the source code of the login page didn't reveal any email addresses I could try to brute force, or anything else of interest. Next, I looked at the request/response headers and cookies of the server. The presence of the X-Powered-By header reveals that the server is running PHP version 5.5.9/Ubuntu. These headers should be disabled on web servers, as attackers can use this information to search for exploits for the current version. Additionally, it appears that we are setting a cookie called HTBBankAuth in our request:

![[Pasted image 20210630144619.png]]

##### robots.txt
No robots.txt file appears to be present on the target, so we cannot use that to find hidden directories.

##### Directory Fuzzing with ffuf
Now that I have a functional hostname, I can use ffuf to fuzz for other possibly interesting directories on the web server. I'm going to use the dirbuster directory-list-2.3-medium.txt wordlist. I'm also going to look for files ending in .txt, .html, .php, .jsp, .cgi, .pl, and .sh:

```
./ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://bank.htb/FUZZ -e .txt,.html,.php,.jsp,.cgi,.pl,.sh
```
 
An interesting directory called balance-transfer is found:

![[Pasted image 20210701102120.png]]

##### balance-transfer Directory
Navigating to the directory in a browser reveals a list of bank accounts, including their username and password, in ACC (Graphic Accounts Data File) format:

![[Pasted image 20210701102415.png]]

![[Pasted image 20210701102443.png]]

The contents of these files appear to be encrypted, and I wasn't sure with what encryption method. I did some searching for .acc file types, and found [a link](https://www.reviversoft.com/file-extensions/acc) to a web site that information about the program that generated these files. The article states that the .acc files were generated from a program called FKJ Software Graphic Accounts. Researching for information about the encryption method that this application uses, I found [an online manual](http://209.68.58.203/manual/files%20and%20security.html) for the software that revealed the following information about the encryption the software uses:

![[Pasted image 20210701122635.png]]

Since it is AES encrypted, it doesn't seem likely that I would be able to crack it.

Manipulating the Last modified and Size filters, I came across a file that was significantly smaller than the rest of the files:

![[Pasted image 20210701121939.png]]

The 68576f20e9732f1b2edc4df5b8533230.acc file is much smaller than the rest of the files, and opening it reveals that the encryption process on this particular file failed:

![[Pasted image 20210701122810.png]]

We now have credentials for a user named Christos Christopoulus that I can use to try and sign in to the site with!

##### Logging In/Initial Shell
Now that we have valid credentials, I validated that they were functional credentials by using them to log in to the web site:

![[Pasted image 20210701123111.png]]

There isn't much to do on the web site other than looking at Chris's account information, and creating a support ticket. Taking a look at the source code of the support page, there is an interesting note found in the comments:

![[Pasted image 20210701125301.png]]

It appears that files uploaded with a .htb extension will get interpreted and executed by PHP on the server. I'll use the [wwwolf PHP webshell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) renamed as index.htb to try and see if I can get a shell through this method:

![[Pasted image 20210701130328.png]]

Uploading the file with a .htb extension succeeds, and I have a functional webshell with www-data privileges!:

![[Pasted image 20210701130507.png]]

##### Upgrading Shell
I want to upgrade from a webshell to a meterpreter shell, so I will start up Metasploit and use the multi/handler module to receive my connection:

![[Pasted image 20210701143342.png]]

I configure LHOST as my interface address for the Hack The Box VPN connection, and configure LPORT as 443. I tend to stick to ports that I know will be allowed through a firewall, such as 80, 443, 53, etc. Using other ports may get blocked by a firewall. Lastly, I use run -j to start the listener as a background job so I am free to continue using Metasploit.

Next I need to figure out how I can initiate the shell from the target machine. I'll use the webshell to see if netcat is installed, which it is:

![[Pasted image 20210701143607.png]]

Now I will use netcat to connect back to my meterpreter listener and get an upgraded shell on the target:

![[Pasted image 20210701143717.png]]

![[Pasted image 20210701143906.png]]

The python -c command gives us a more interactive terminal than what the meterpreter shell (and pretty much every other initial shell) will. Exploring the home directory, we see a single user named chris on the system and can get the user.txt flag:

![[Pasted image 20210701144106.png]]

##### Privilege Escalation
Now that I know there is a user named chris on the system, I tried to switch user (su) to him, but it doesn't seem that he has reused his password for his system account. It's always a good practice to try and reuse credentials as users are often lazy and won't pick a unique password for each account:

![[Pasted image 20210701144625.png]]

Next I will begin obtaining more information about the target system. I will set up a python HTTP server on my machine to host [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), which is an excellent privilege escalation enumeration tool for Linux:

![[Pasted image 20210701145224.png]]

Linpeas provides a huge amount of output, and you should look at every line of it. While it is time consuming, privilege escalation requires patience and a solid understanding of the target.

##### Root Method 1
A common way to escalate privileges on a Linux host is by abusing binaries/scripts that have a SUID of root set. Linpeas can search for these files, and one of particular interest pops up:

![[Pasted image 20210701152904.png]]

Inside the /var/htb folder, there is a SUID script called emergency. Looking at the content of the script, it is a python script that appears to give immediate root access by simplying answering y at the prompt it gives:

![[Pasted image 20210701153114.png]]

![[Pasted image 20210701153203.png]]

When you answer y, the script calls a binary located in the /var/htb/bin folder called emergency. Whatever the underlying code of this program is doing, it gives a root shell which is good for us and bad for our target. We can now access the root flag!:

![[Pasted image 20210701155111.png]]

##### Root Method 2
Linpeas also discovered that the /etc/passwd file is writable. Modern Linux systems use the /etc/shadow file for storing passwords, but if you have a user with a hashed password in the /etc/passwd file, then that password will be honored first instead of one in the /etc/shadow file. Since I can write to the /etc/passwd file, I will just make myself a backdoor account with root permissions to access the target:

![[Pasted image 20210701154724.png]]

![[Pasted image 20210701154758.png]]

I hope you enjoyed this write-up of Bank from Hack The Box! Happy Hacking!