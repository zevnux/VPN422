

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
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
	private byte[] SHARED_KEY;
	private BigInteger nonce;
	
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
		try {
			socket.getInetAddress();
			return InetAddress.getLocalHost().toString();
		} catch (UnknownHostException e) {		
			e.printStackTrace();
			return null;
		}
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
	
	public void listenForMessage(){
		try{
			while (true){
				if (channel.getInputStream().available() != 0){
					String plainText = "";
					DataInputStream dis = new DataInputStream(channel.getInputStream());
					byte[] clientMessage = new byte[channel.getInputStream().available()];
					dis.readFully(clientMessage);
					System.out.println("Received the following encrypted message from server: ");
					System.out.println(bytesToHex(clientMessage));
					plainText = AES.decrypt(clientMessage, SHARED_KEY);
					System.out.println("Plaintext is: ");
					System.out.println(plainText);
				}
			}	
		} catch (Exception e){
			e.printStackTrace();
		}

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
	
//	public void waitForClientKey(){
//		try{
//			if (channel.getInputStream().available() != 0){
//				DataInputStream input = new DataInputStream(channel.getInputStream());
//				System.out.println(input.readUTF());
//				getClientSecretKey(input.readUTF());
//				genSessionKey();
//				System.out.println("Session key: " + SESSION_KEY.toString());
//			}
//		} catch (IOException e){
//			e.printStackTrace();
//		} catch (Exception e){
//			e.printStackTrace();
//		}
//	}
	
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
						byte[] encryptedMessage;
						encryptedMessage = AES.encrypt(message, SHARED_KEY);				
						System.out.println("The encrypted message being sent to the client is: ");
						System.out.println(bytesToHex(encryptedMessage));
						DataOutputStream output = new DataOutputStream(channel.getOutputStream());
						output.write(encryptedMessage);
					}	
				} catch (Exception e){
					e.printStackTrace();
				}

			}
		};
		
		Thread writer = new Thread(r);
		writer.start();
		
	}
	
//	private void getClientSecretKey(String readUTF) throws Exception {
//		String[] receivedMessage = readUTF.split("~");
//		String clientKey = receivedMessage[1];
//		if(!clientKey.matches("[0-9]*")){
//			throw new Exception("unexpected client key value");
//		}
//		CLIENT_SECRET_KEY = new BigInteger(clientKey);
//	}
	
	/**
	 * generate the diffie-hellman session key
	 * @return
	 */
	private boolean genSessionKey() {
		SESSION_KEY = DiffieHellman.dhMod(CLIENT_SECRET_KEY, a, p);
		return true;
	}
	
	/**
	 * calculate the diffie-hellman secret key for the server
	 */
	private void initSecretKey() {
		SECRET_KEY = DiffieHellman.dhMod(g, a, p);
	}
	
	/**
	 * generate a diffie-hellman secret value for the server
	 */
	private void genSecretKey() {
		a = DiffieHellman.generateRandomSecretValue();
	}
	
	/**
	 * generate a diffie-hellman prime number for the session
	 */
	private void genP() {
		p = DiffieHellman.generateBigIntPrime();
	}
	
	/**
	 * generate a diffie-hellman G value for the session
	 */
	private void genG() {
		g = DiffieHellman.generateBigIntG();
	}

	public void listenThenSendChallenge() {
		String clientNonce = "";
		nonce = DiffieHellman.generateRandomSecretValue();
		try{	
			// Block while waiting for input
			while(channel.getInputStream().available() == 0);
			// By the time we get here we have input to read (initial message)
			DataInputStream input = new DataInputStream(channel.getInputStream());
			
			String message = input.readUTF();
			
			
			System.out.println(message);
			clientNonce = message.split("~")[1];
			System.out.println("The client nonce is: " + clientNonce);
			
			// Send back server nonce in clear
			// Encrypt signature + clientNonce + powmodServer with SharedSecretKey
			String messageEncryptToClient = "IAmServer~" + clientNonce + "~" + SECRET_KEY.toString();
			System.out.println("My message to the client is: " + messageEncryptToClient);
			byte[] encryptedMessage;
			try {
				encryptedMessage = AES.encrypt(messageEncryptToClient, SHARED_KEY);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
			
			DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
			dos.writeUTF(nonce.toString());
			System.out.println("My nonce is: " + nonce);
			
			DataOutputStream output = new DataOutputStream(channel.getOutputStream());
			output.write(encryptedMessage);
			
			// This is to test the decryption was working properly
//			try {
//				String decrypted  = AES.decrypt(encryptedMessage, SHARED_KEY);
//				System.out.println(decrypted);
//			} catch (Exception e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void listenForResponseFromClient(){
		// Get the encrypted text and decrypt it
		String plainText = "";
		try{
			while(channel.getInputStream().available() == 0);
			DataInputStream input = new DataInputStream(channel.getInputStream());
			byte[] serverMessage = new byte[channel.getInputStream().available()];
			input.readFully(serverMessage);
			plainText = AES.decrypt(serverMessage, SHARED_KEY);
			System.out.println("Plaintext is: " + plainText);
		} catch (Exception e){
			e.printStackTrace();
		}
		String myNonceCheck = plainText.split("~")[1];
		CLIENT_SECRET_KEY = new BigInteger(plainText.split("~")[2]);
		if (myNonceCheck.equals(nonce.toString())){
			System.out.println("Verified client sent back correct encrypted nonce, successfully authenticated client");
			// If the client authenticated okay, we can start sending messages back to each other using the session Key!
			genSessionKey();
			System.out.println("The shared session key is: " + SESSION_KEY.toString());
			
		} else {
			// If the server is fake, get out and close the socket
			System.out.println("That server is a fake! GET OUT!!!!!");
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
	
	public void setHashedKey(byte[] hashedKey) {
		SHARED_KEY = hashedKey;
	}
	
	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder();
	    for (byte b : bytes) {
	        sb.append(String.format("%02X", b));
	    }
	    return sb.toString();
	}
}
