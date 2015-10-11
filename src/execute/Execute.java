package execute;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Scanner;

import client.Client;
import server.Server;

public class Execute {
	
	public static void main(String[] args) {
		Scanner reader = new Scanner(System.in);
		System.out.println("Welcome to SDC Secure Messaging!");
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
			runClient();	
		} else if (mode.equalsIgnoreCase("server")){
			System.out.println("Initializing a new server...");
			runServer();	
		}
		
		reader.close();
	}
	
	private static void runClient(){
		String hostname;
		int port;
				
		Scanner reader = new Scanner(System.in);
		System.out.println("Please input the hostname or IP Address of the server you wish to connect to");
		hostname = reader.next();
		System.out.println("Please input the port of the server you wish to connect to");
		port = reader.nextInt();
		
		Client c = new Client();
	
		c.connectToServer(hostname, port);
		System.out.println("Communication channel established with " + c.getSocket().getRemoteSocketAddress().toString());
		c.listenToServer();
		reader.nextLine();
		
		
		try {
			while (true){
				String message = reader.nextLine();
				DataOutputStream dos = new DataOutputStream(c.getSocket().getOutputStream());
				dos.writeUTF(message);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	private static void runServer(){
		int port;
		Scanner reader = new Scanner(System.in);
		
		System.out.println("Please input the port for your server");
		port = reader.nextInt();
		
		Server s = new Server();
		s.bindSocket(port);
		System.out.println("The server is listening on the address " + s.getIp() + ":" + s.getPort());
		System.out.println("Waiting for client...");
		s.waitForClient();
		s.writeToClient();
		
		System.out.println("Communication channel established with " + s.getChannel().getInetAddress().getHostName());
		try{
			while(true){
				if (s.getChannel().getInputStream().available() != 0){
					DataInputStream input = new DataInputStream(s.getChannel().getInputStream());
					System.out.println("Client Says: " + input.readUTF());
				}
			}
		} catch (IOException e){
			e.printStackTrace();
		}
			
		
		
		
	}
	
}
