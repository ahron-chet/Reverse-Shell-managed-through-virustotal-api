# Reverse Shell Managed Through VirusTotal API
This repository contains a reverse shell that allows an attacker to remotely control a compromised system and execute commands on it through the use of the VirusTotal API. 
All communication between the client and server is completely encrypted using AES encryption.
The program is designed to not be detected or blocked by any AV/EDR systems.

The shell works by using VirusTotal to transfer data between the client (the attacker's system) and the server (the compromised system). A unique file hash is used as an identifier to communicate between the client and server. The repository includes two scripts: one for the client side and one for the server side.

# To use the shell, follow these steps:

- Upload a random file to the VirusTotal website.
- Copy the file hash and paste it into the hashSource variable at the top of the code for both the client and server scripts.
- Copy your VirusTotal API key and paste it into the ApiVt variable for both the client and server scripts.
- Run the client script on the attacker's system and the server script on the compromised system.

Once these steps are completed, the shell will be ready to use. The client can use the shell to execute commands on the server and receive the output. Please note that the use of this tool may be illegal in certain circumstances and could result in criminal charges. Use at your own risk.
