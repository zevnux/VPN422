

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class Server {
	private ServerSocket socket;
	private Socket channel;
	
	public void bindSocket (int port) {
		try{
			socket = new ServerSocket(port);
		} catch (IOException e){
			System.out.println("Failed to bind port " + port + " to socket; already in use");
		}
	}
	
	public Socket getChannel(){
		return channel;
	}
	
	public int getPort(){
		return socket.getLocalPort();
	}
	
	public String getIp(){
		return socket.getInetAddress().getHostName().toString();
	}
	
	public void waitForClient(){
		try {
			channel = socket.accept();
		} catch (IOException e){
			System.out.println("Error! LOLs!");
		}
	}
	
	public ServerSocket getSocket(){
		return socket;
	}
	
	/**
	 * This is to be run after a connection to the client, as to allow the server to send messages to the client without interfering with input
	 * Once the connection to the server is established, the server will send another connection request back
	 */
	public void writeToClient(){
		Runnable r = new Runnable(){
			public void run () {
				Scanner reader = new Scanner(System.in);
				try{
					while (true){
						String message = reader.nextLine();
						DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
						dos.writeUTF(message);
					}	
				} catch (IOException e){
					e.printStackTrace();
				}

			}
		};
		
		Thread writer = new Thread(r);
		writer.start();
		
	}
}
