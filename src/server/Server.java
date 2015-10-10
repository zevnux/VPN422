package server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
	private ServerSocket socket;
	
	public void bindSocket (int port) {
		try{
			socket = new ServerSocket(port);
		} catch (IOException e){
			System.out.println("Failed to bind port " + port + " to socket; already in use");
		}
	}
	
	public ServerSocket getSocket(){
		return socket;
	}
}
