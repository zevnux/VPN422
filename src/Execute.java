
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
			// Begin initial questions for the user
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			System.out.println("Welcome to SDC Secure Messaging!");
			System.out.println("Please enter the secret shared key you wish to use");
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
			

		} catch (Exception e) {
			e.printStackTrace();
			reader.close();
			return;
		}
		reader.close();
	}
	
	private static void runClient(byte[] hashedKey){
		String hostname;
		int port;
		boolean connected = false;
				
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
		c.getDiffieHellmanValues();
		c.sendInitialMessage();
		connected = c.getChallengeFromServerAndSendResponse();
		if (connected){
			System.out.println("Communication channel established with " + c.getSocket().getRemoteSocketAddress().toString());
			c.listenToServer();
			c.sendMessage();
		} else {
			try {
				c.getSocket().close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		reader.close();
	}
	
	private static void runServer(byte[] hashedKey){
		int port;
		Scanner reader = new Scanner(System.in);
		boolean connected = false;
		
		System.out.println("Please input the port for your server");
		port = reader.nextInt();

		
		Server s = new Server();
		s.setHashedKey(hashedKey);

		
		s.bindSocket(port);
		System.out.println("The server is listening on the address " + s.getIp() + ":" + s.getPort());
		System.out.println("Waiting for client...");
		s.waitForClient();
		System.out.println("Client attempting secure connection");
		s.sendDiffieHellmanValues();
		s.listenThenSendChallenge();
		connected = s.listenForResponseFromClient();
		if (connected){
			System.out.println("Communication channel established with " + s.getChannel().getLocalSocketAddress().toString());
			s.writeToClient();
			s.listenForMessage();
		} else {
			try {
				s.getChannel().close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		reader.close();
	}
	
}
