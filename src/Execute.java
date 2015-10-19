

import java.io.DataInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class Execute {
	
	public static void main(String[] args) {
		Scanner reader = new Scanner(System.in);
		String sharedSecretKey = "";
		byte[] hashedKey;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			System.out.println("Welcome to SDC Secure Messaging!");
			System.out.println("Please enter the secret shared key");
			sharedSecretKey = reader.nextLine();
			byte[] hash = md.digest(sharedSecretKey.getBytes("UTF-8"));	
			hashedKey = Arrays.copyOf(hash, 16);
			System.out.println("Please choose 'client' or 'server' mode");
			// Make sure we get valid input to choose between a client or server
			String mode = reader.next();
			while (!mode.equalsIgnoreCase("client") && !mode.equalsIgnoreCase("server")){
				System.out.println("Unable to understand input, please try again");
				mode = reader.next();
			}

			// Once we have valid input, we'll look into the separate functions of running a client or server
			if (mode.equalsIgnoreCase("client")){
				System.out.println("Initializing a new client...");
				runClient(hashedKey);	
			} else if (mode.equalsIgnoreCase("server")){
				System.out.println("Initializing a new server...");
				runServer(hashedKey);	
			}
			
			reader.close();
		} catch (Exception e) {
			System.out.println("OMG, NO MAS");
			e.printStackTrace();
			reader.close();
			return;
		}
	}
	
	private static void runClient(byte[] hashedKey){
		String hostname;
		int port;
				
		Scanner reader = new Scanner(System.in);
		System.out.println("Please input the hostname or IP Address of the server you wish to connect to");
		hostname = reader.next();
		System.out.println("Please input the port of the server you wish to connect to");
		port = reader.nextInt();
		
		Client c = new Client();
		c.setHashedKey(hashedKey);
	
		c.connectToServer(hostname, port);
		// For some reason, needs to clear next line before sending message after connection
		reader.nextLine();
		c.sendInitialMessage();
		c.getDiffieHellmanValues();
		c.getChallengeFromServerAndSendResponse();
		System.out.println("Communication channel established with " + c.getSocket().getRemoteSocketAddress().toString());
		c.listenToServer();
		c.sendMessage();
	}
	
	private static void runServer(byte[] hashedKey){
		int port;
		Scanner reader = new Scanner(System.in);
		
		System.out.println("Please input the port for your server");
		port = reader.nextInt();
		
		Server s = new Server();
		s.setHashedKey(hashedKey);
		
		s.bindSocket(port);
		System.out.println("The server is listening on the address " + s.getIp() + ":" + s.getPort());
		System.out.println("Waiting for client...");
		s.waitForClient();
		s.sendDiffieHellmanValues();
		s.listenThenSendChallenge();
		s.listenForResponseFromClient();
		System.out.println("Communication channel established with " + s.getChannel().getLocalSocketAddress().toString());
		s.writeToClient();
		s.listenForMessage();		
	}
	
}
