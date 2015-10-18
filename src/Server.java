

import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class Server {
	private ServerSocket socket;
	private Socket channel;
	private BigInteger a;
	private BigInteger p;
	private BigInteger g;
	private BigInteger SECRET_KEY;
	
	public void bindSocket (int port) {
		try{
			socket = new ServerSocket(port);
			genSecretKey();
			genP();
			genG();
			initSecretKey();
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
	
	public void establishSessionKey(){
		Runnable r = new Runnable(){
			public void run () {
				try{
					String message = "\nThe g value is: ~" + g.toString() + 
							"~\nThe p value is: ~" + p.toString() + 
							"~\nMy DH Mod is: ~" + SECRET_KEY.toString() + "~\n";
					DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
					dos.writeUTF(message);
				} catch (IOException e){
					e.printStackTrace();
				}
			}
		};
		Thread writer = new Thread(r);
		writer.start();
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
	
	private void initSecretKey() {
		SECRET_KEY = DiffieHellman.dhMod(g, a, p);
	}
	
	private void genSecretKey() {
		a = DiffieHellman.generateRandomSecretValue();
	}
	
	private void genP() {
		p = DiffieHellman.generateBigIntPrime();
	}
	
	private void genG() {
		g = DiffieHellman.generateBigIntG();
	}
}
