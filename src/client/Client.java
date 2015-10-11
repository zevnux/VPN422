package client;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {

	private Socket socket;
	
	public void connectToServer(String host, int port){
		try{
			socket = new Socket(host, port);
		} catch (UnknownHostException e){
			System.out.println("Failed to connect to server; unknown host");
		} catch (IOException e){
			System.out.println("Failed to connect to server; bad port");
		}
	}
	
	public Socket getSocket(){
		return socket;
	}
	
	public void sendMessage(String message){
		
	}
	
	
	/**
	 * This is to be run after a connection to the server, as to allow the client to receive messages from the server without interfering with input
	 * Once the connection to the server is established, the server will send another connection request back
	 */
	public void listenToServer(){
		Runnable r = new Runnable(){
			public void run () {
				try{
					while (true){
						if (socket.getInputStream().available() != 0){
							DataInputStream input = new DataInputStream(socket.getInputStream());
							System.out.println("Server Says: " + input.readUTF());
						}
					}	
				} catch (IOException e){
					e.printStackTrace();
				}

			}
		};
		
		Thread listener = new Thread(r);
		listener.start();
		
	}
	
}
