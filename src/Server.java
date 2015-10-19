

import java.io.DataInputStream;
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
	private BigInteger CLIENT_SECRET_KEY;
	private BigInteger SESSION_KEY;
	private String SHARED_KEY;
	
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
	
	public void sendDiffieHellmanValues(){
		try{
			String message = "\nThe g value is: ~" + g.toString() + 
					"~\nThe p value is: ~" + p.toString() + "~\n";
			DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
			dos.writeUTF(message);
		} catch (IOException e){
			e.printStackTrace();
		}
	}
	
	public void waitForClientKey(){
		Runnable r = new Runnable(){
			public void run () {
				try{
					if (channel.getInputStream().available() != 0){
						DataInputStream input = new DataInputStream(channel.getInputStream());
						System.out.println(input.readUTF());
						getClientSecretKey(input.readUTF());
						genSessionKey();
						System.out.println("Session key: " + SESSION_KEY.toString());
					}
				} catch (IOException e){
					e.printStackTrace();
				} catch (Exception e){
					e.printStackTrace();
				}
				
			}
		};
		Thread listener = new Thread(r);
		listener.start();
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
	
	private void getClientSecretKey(String readUTF) throws Exception {
		String[] receivedMessage = readUTF.split("~");
		String clientKey = receivedMessage[1];
		if(!clientKey.matches("[0-9]*")){
			throw new Exception("unexpected client key value");
		}
		CLIENT_SECRET_KEY = new BigInteger(clientKey);
	}
	
	private boolean genSessionKey() {
		SESSION_KEY = DiffieHellman.dhMod(CLIENT_SECRET_KEY, a, p);
		return true;
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

	public void listenThenSendChallenge() {
		String clientNonce = "";
		BigInteger nonce = DiffieHellman.generateRandomSecretValue();
		try{	
			// Block while waiting for input
			while(channel.getInputStream().available() == 0);
			// By the time we get here we have input to read (initial message)
			DataInputStream input = new DataInputStream(channel.getInputStream());
			
			String message = input.readUTF();
			
			
			System.out.println(message);
			clientNonce = message.split("~")[1];
			System.out.println(clientNonce);
			
			// Send back server nonce in clear
			// Encrypt signature + clientNonce + powmodServer with SharedSecretKey
			String messageEncryptToClient = "IamServer~" + clientNonce + "~" + SECRET_KEY.toString();
			String encryptedMessage;
			try {
				System.out.println("got here");
				encryptedMessage = new String (AES.encrypt(messageEncryptToClient, SHARED_KEY));
				System.out.println(encryptedMessage);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
			
			DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
			dos.writeUTF(nonce + "~" + encryptedMessage);
			System.out.println(encryptedMessage);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void setHashedKey(String hashedKey) {
		SHARED_KEY = hashedKey;
	}
}
