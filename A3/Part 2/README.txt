>> PLEASE READ EVERYTHING <<

  - I have also provided a video called BUILD_GUIDE_VIDEO.mkv that you can watch if you have any trouble with the instructions

Compilation:
  - Compilation is done using Apache ANT (https://ant.apache.org/), it is the simplest build tool I know of.
  - I have provided a compiled folder called "artefact". If you can't get building to work you can follow 'Execution' instructions using 'cd artefact' instead of 'cd build'
  - Build definition is located in 'build.xml'

	Instructions
		1. Enter Root Directory
    2. 'ant clean'
    3. 'ant compile'

Execution:
	 - Execute A3Server First, and A3Client second!
	 - [port] is the port to use. you can use any port, example 4444

	Instructions
	 1. Enter the newly created folder 'cd build'
	 2. 'java A3Server [port]'
	 3. 'java A3Client [port]'

Source Code:
	- Most source code is located in /src 
	- Source code is categorized into folders. Description of important folders and files is noted below in "Program Description"

Output
	- All byte arrays are displayed as integers
	- Output will mention all of the packets sent in the following format
	- In the following example the client sent the setup request hello packet containing the message hello 
		[Client] Sending: Client Setup Request Hello: {
  			"message": Hello!
		}
	- in the data exchange messages there is a little header as shown below, this is logged before encryption of the message to demonstrate that the sent message is the same as the retrieved message after encryption/decryption
	[Server] ---------------------------
	[Server] SENT MESSAGE: This is an awesome data exchange. I need 64 character. Message#1
	[Server] ---------------------------


Note
  	- Examples.java = examples of all of the crypto-systems being used individually. This can be optionally run using 'java Examples' to demonstrate each individual crypto-system working.

Program Description
  - /crypto contains the most important files 
  	- MathHelper.java = Fast Modular Exponentiation 
  	- RSA.java = RSA digital signature implementation
  	- DHE_RSA_SHA256.java = Diffie Hellman Key Exchange 
  	- AESCryptoSystem.java = CBC Mode - DH Key Exchange

  - /packets contains all of the information being sent between the client and the server 
  	- Naming Scheme: Packet [Client/Server] [Protocol] [Name] for example, PacketServerHandshakeHello.java
  	- Packets are sent over the sockets using the object output stream.
  	- PacketDataExchange - Performs the message exchange, calculates the HMAC and performs CBC on the inputted message. On the receiving end will throw a TamperedMessageException if the HMAC's do not match. 

  - /client
  	- ServerConnection =  The connection between the client and the server using a socket. 
  	- SecureClient = Represents the client, serverconection abstracts the sockets away 
  	- /protocol
  		- Protocols used by the client

  - /server
  	- ClientConnection = The connection between the server and the client using a socket
  	- SecureServer = Represents the server using sockets. Currently the server only supports one client but this could easily be upgraded
  	- SecureSession = Represents a client from the servers perspective, the clientconnection abstracts away the sockets. 
  	- /protocol
  		- Protocols used by the server


  - Everything else is just some kind of abstraction, utility or socket level communication which isn't very important for your marking!
