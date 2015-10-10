package execute;

import java.util.Scanner;

import client.Client;
import server.Server;

public class Execute {
	
	public static void main(String[] args) {
		Scanner reader = new Scanner(System.in);
		System.out.println("Welcome to SDC Secure Messaging!");
		System.out.println("Please choose 'client' or 'server' mode");
		
		String mode = reader.next();
		while (!mode.equalsIgnoreCase("client") && !mode.equalsIgnoreCase("server")){
			System.out.println("Unable to understand input, please try again");
			mode = reader.next();
		}
	
		if (mode.equalsIgnoreCase("client")){
			System.out.println("Initializing a new client...");
			Client c = new Client();
		} else if (mode.equalsIgnoreCase("server")){
			System.out.println("Initializing a new server...");
			Server s = new Server();
	
		}
	}
	
}
