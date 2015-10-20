

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Server {
	private ServerSocket socket;
	private Socket channel;
	private BigInteger a;
	private BigInteger p;
	private BigInteger g;
	private BigInteger SECRET_KEY;
	private BigInteger CLIENT_SECRET_KEY;
	private byte[] SESSION_KEY;
	private byte[] SHARED_KEY;
	private byte[] INTEGRITY_KEY;
	private String IV;
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
					// Separate the encrypted message from the mac
					byte[] message = Arrays.copyOf(clientMessage, clientMessage.length-32);	
					plainText = AES.decrypt(message, SESSION_KEY, IV);
					System.out.println("Plaintext is: ");
					System.out.println(plainText);
					Mac mac = Mac.getInstance("HmacSHA256");
			        mac.init(new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256"));
			        byte[] calculatedMac = mac.doFinal(Arrays.copyOfRange(message, message.length-16, message.length));
					byte[] macFromClient = Arrays.copyOfRange(clientMessage, clientMessage.length-32, clientMessage.length);
					if (Arrays.equals(macFromClient, calculatedMac)){
						System.out.println("Successfully verified the integrity of the message");
					} else {
						System.out.println("Message could not ber verified!!!!");
					}
				}
			}	
		} catch (Exception e){
			e.printStackTrace();
		}

	}
	
	public void sendDiffieHellmanValues(){
		try{
			computeIV();
			String message = "\nThe g value is: ~" + g.toString() + 
					"~\nThe p value is: ~" + p.toString() + 
					"~\n The IV is: ~" + IV + "~\n";
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
						encryptedMessage = AES.encrypt(message, SESSION_KEY, IV);				
						System.out.println("The encrypted message being sent to the client is: ");
						System.out.println(bytesToHex(encryptedMessage));
						DataOutputStream output = new DataOutputStream(channel.getOutputStream());
						
				        // Send the MAC after we send the message
				        Mac mac = Mac.getInstance("HmacSHA256");
				        mac.init(new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256"));
				        output.write(encryptedMessage);
				        output.write(mac.doFinal(Arrays.copyOfRange(encryptedMessage, encryptedMessage.length-16, encryptedMessage.length)));
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
	
	private void genSessionKey() {
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String sessionString = DiffieHellman.dhMod(CLIENT_SECRET_KEY, a, p).toString();
			byte[] hash = md.digest(sessionString.getBytes("UTF-8"));	
			SESSION_KEY = Arrays.copyOf(hash, 16);
		} catch (Exception e){
			e.printStackTrace();
		}
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
				encryptedMessage = AES.encrypt(messageEncryptToClient, SHARED_KEY, IV);
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
			plainText = AES.decrypt(serverMessage, SHARED_KEY, IV);
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
			System.out.println("The shared session key is: " + DiffieHellman.dhMod(CLIENT_SECRET_KEY, a, p).toString());
			
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
		computeIntegrityKey();
	}
	
	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder();
	    for (byte b : bytes) {
	        sb.append(String.format("%02X", b));
	    }
	    return sb.toString();
	}
	
	/**
	 * Compute the hash of the hash of the shared secrety key, we'll use this as the
	 * integrity key since it's already a known shared value
	 */
	private void computeIntegrityKey(){
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(SHARED_KEY);
			INTEGRITY_KEY = Arrays.copyOf(hash, 16);
		} catch (Exception e){
			e.printStackTrace();
		}
	}
	
	  private void computeIV(){
		 String randomNum = DiffieHellman.generateRandomSecretValue().toString();
		 String vector = randomNum.substring(0, 16);
		 IV = vector;
	  }
}
