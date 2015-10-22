

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
	private String myPhrase;
	
	/**
	 * Bind the socket for communication
	 * @param port
	 */
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
			e.printStackTrace();
		}
	}
	
	public ServerSocket getSocket(){
		return socket;
	}
	
	/**
	 * Main function for listening for server once a mutual authentication is established
	 */
	public void listenForMessage(){
		try{
			// Go indefinitely once connection is established
			while (true){
				if (channel.getInputStream().available() != 0){
					// Grab the data from the socket
					String plainText = "";
					DataInputStream dis = new DataInputStream(channel.getInputStream());
					byte[] clientMessage = new byte[channel.getInputStream().available()];
					dis.readFully(clientMessage);
					System.out.println("Received the following encrypted message from server: ");
					
					// Separate the encrypted message from the mac
					byte[] message = Arrays.copyOf(clientMessage, clientMessage.length-32);	
					System.out.println(bytesToHex(message));
					plainText = AES.decrypt(message, SESSION_KEY, IV);
					System.out.println("Plaintext is: ");
					System.out.println(plainText);
					
					// Calculate the MAC from the last block of the cipher
					// and then compare it to the one the client sent
					Mac mac = Mac.getInstance("HmacSHA256");
			        mac.init(new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256"));
			        byte[] calculatedMac = mac.doFinal(Arrays.copyOfRange(message, message.length-16, message.length));
					byte[] macFromClient = Arrays.copyOfRange(clientMessage, clientMessage.length-32, clientMessage.length);
					System.out.println("The mac received is: \n" + bytesToHex(macFromClient));
					System.out.println("The mac calculated from the message is: \n" + bytesToHex(calculatedMac));
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
	
	/**
	 * Broadcast the public values p, g, and the IV to the client
	 */
	public void sendDiffieHellmanValues(){
		try{
			computeIV();
			String message = "The g value is: ~" + g.toString() + 
					"~\nThe p value is: ~" + p.toString() + 
					"~\nThe IV is: ~" + IV + "";
			System.out.println("Sending the following values to the client: \n" + message);
			DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
			dos.writeUTF(message);
		} catch (IOException e){
			e.printStackTrace();
		}
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
						//Read the message input from the console and encrypt it
						String message = reader.nextLine();
						byte[] encryptedMessage;
						encryptedMessage = AES.encrypt(message, SESSION_KEY, IV);				
						System.out.println("The encrypted message being sent to the client is: ");
						System.out.println(bytesToHex(encryptedMessage));
						DataOutputStream output = new DataOutputStream(channel.getOutputStream());
						
				        // Send the MAC after we send the message
				        Mac mac = Mac.getInstance("HmacSHA256");
				        mac.init(new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256"));
				        byte[] macToClient = mac.doFinal(Arrays.copyOfRange(encryptedMessage, encryptedMessage.length-16, encryptedMessage.length));
				        System.out.println("The mac being sent to the client is: ");
						System.out.println(bytesToHex(macToClient));
				        output.write(encryptedMessage);
				        output.write(mac.doFinal(Arrays.copyOfRange(encryptedMessage, encryptedMessage.length-16, encryptedMessage.length)));
					}	
				} catch (Exception e){
					e.printStackTrace();
				}
				reader.close();
			}
		};
		
		Thread writer = new Thread(r);
		writer.start();	
	}
	
	/**
	 * generate the diffie-hellman session key
	 * @return
	 */
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

	/**
	 * Listens to the client's initial message to the server for the nonce
	 * Once received, sends the following challenge to the client
	 * myNonce, E(myPhrase~ClientNonce~g^amodp)_SHARED_KEY
	 */
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
			myPhrase = DiffieHellman.generateRandomSecretValue().toString();
			String messageEncryptToClient = myPhrase + "~" + clientNonce + "~" + SECRET_KEY.toString();
			System.out.println("My message to the client is: " + messageEncryptToClient);
			byte[] encryptedMessage;
			encryptedMessage = AES.encrypt(messageEncryptToClient, SHARED_KEY, IV);
			
			//Send the nonce after as a string
			DataOutputStream dos = new DataOutputStream(channel.getOutputStream());
			dos.writeUTF(nonce.toString());
			System.out.println("My nonce is: " + nonce);
			DataOutputStream output = new DataOutputStream(channel.getOutputStream());
			// Make sure the previous input is read before writing to the socket again
			while (channel.getInputStream().available() != 0);
			output.write(encryptedMessage);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Handles the client's challenge response
	 */
	public boolean listenForResponseFromClient(){
		// Get the encrypted text and decrypt it
		String plainText = "";
		try{
			while(channel.getInputStream().available() == 0);
			DataInputStream input = new DataInputStream(channel.getInputStream());
			byte[] clientMessage = new byte[channel.getInputStream().available()];
			input.readFully(clientMessage);
			plainText = AES.decrypt(clientMessage, SHARED_KEY, IV);
			System.out.println("Plaintext is: " + plainText);
		} catch (Exception e){
			e.printStackTrace();
		}
		
		// Make sure the personal message is not the one we sent out
		String clientPhrase = plainText.split("~")[0];
		if (clientPhrase.equals(myPhrase)){
			System.out.println("Received original message back, replay attack!");
			return false;
		}
		System.out.println("Confirmed the message was not the same, continue with nonce check");
		
		// Phrase was not the same, we're good to check the nonce
		// Check the nonce
		String myNonceCheck = plainText.split("~")[1];
		CLIENT_SECRET_KEY = new BigInteger(plainText.split("~")[2]);
		if (myNonceCheck.equals(nonce.toString())){
			System.out.println("Verified client sent back correct encrypted nonce, successfully authenticated client");
			// If the client authenticated okay, we can start sending messages back to each other using the session Key!
			genSessionKey();
			System.out.println("The shared session key is: " + DiffieHellman.dhMod(CLIENT_SECRET_KEY, a, p).toString());	
			return true;
		} else {
			// If the client is fake, get out and close the socket
			System.out.println("That client is a fake! GET OUT!!!!!");
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return false;

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
