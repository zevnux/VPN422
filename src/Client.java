

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Client {

	private Socket socket;
	private BigInteger b;
	private BigInteger p;
	private BigInteger g;
	private BigInteger SERVER_SECRET_KEY;
	private byte[] SESSION_KEY;
	private BigInteger SECRET_KEY;
	private BigInteger nonce; 
	private byte[] SHARED_KEY;
	private byte[] INTEGRITY_KEY;
	private String IV;
	private Object myPhrase;
	
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
	
	/**
	 * This method is used as the main way the client sends messages
	 * to the server once the authentication is complete
	 */
	public void sendMessage(){
		Scanner reader = new Scanner(System.in);
		try {
			// Loop indefinitely until the client is closed
			while (true){
				// Read the user input, then encrypt it
				String message = reader.nextLine();
				byte[] encryptedMessage;
				encryptedMessage = AES.encrypt(message, SESSION_KEY, IV);				
				System.out.println("The encrypted message being sent to the server is: ");
				System.out.println(bytesToHex(encryptedMessage));
				DataOutputStream output = new DataOutputStream(socket.getOutputStream());
				
				 // Send the MAC after we send the message
		        Mac mac = Mac.getInstance("HmacSHA256");
		        mac.init(new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256"));
		        byte[] macToServer = mac.doFinal(Arrays.copyOfRange(encryptedMessage, encryptedMessage.length-16, encryptedMessage.length));
		        System.out.println("The mac being sent to the server is: ");
				System.out.println(bytesToHex(macToServer));
		        output.write(encryptedMessage);
		        output.write(mac.doFinal(Arrays.copyOfRange(encryptedMessage, encryptedMessage.length-16, encryptedMessage.length)));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		reader.close();
	}
	
	/**
	 * 	Listen to the server for the g and p values. Then send the client's Diffie-hellman value to the server.
	 * 	Also save the session key. 	
	 */
	public void getDiffieHellmanValues(){
		try{
			System.out.println("Waiting for server to send p, g, and IV");
			while (socket.getInputStream().available() == 0);
			DataInputStream input = new DataInputStream(socket.getInputStream());
			String serverMessage = input.readUTF();
			System.out.println("Received the following values from server: \n" + serverMessage);
			scrapeGValue(serverMessage);
			scrapePValue(serverMessage);
			scrapeIV(serverMessage);
			createSecretKey();
		} catch (IOException e){
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Scrape the IV from the message from the server
	 * @param readUTF
	 * @throws Exception
	 */
	private void scrapeIV(String readUTF) throws Exception {
		String IVValue = readUTF.split("~")[5]; //hardcode
		if(!IVValue.matches("[0-9]*")){
			throw new Exception("unexpected IV value");
		}
		
		IV = new BigInteger(IVValue).toString();
		
	}

	/**
	 * Client will create the secret key. 
	 */
	private void createSecretKey() {
		genSecretValue(); //little b
		initSecretKey();
		System.out.println("Client g^nmodp value: ~" + SECRET_KEY.toString() + "~");
	}
	
	private void scrapeGValue(String readUTF) throws Exception {
		String gValue = readUTF.split("~")[1]; //hardcode
		if(!gValue.matches("[0-9]*")){
			throw new Exception("unexpected G value");
		}
		
		g = new BigInteger(gValue);
	}
	
	private void scrapePValue(String readUTF) throws Exception {
		String pValue = readUTF.split("~")[3]; //hardcode
		if(!pValue.matches("[0-9]*")){
			throw new Exception("unexpected P value");
		}
		
		p = new BigInteger(pValue);
	}
	
	
	/**
	 * generate a diffie-hellman secret value to be used for the client
	 */
	private void genSecretValue() {
		b = DiffieHellman.generateRandomSecretValue();
	}

	/**
	 * generate the diffie-hellman secret key for the client
	 */
	private void initSecretKey() {
		SECRET_KEY = DiffieHellman.dhMod(g, b, p);
	}
	
	/**
	 * generate the diffie-hellman session key
	 */
	private void genSessionKey() {
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String sessionString = DiffieHellman.dhMod(SERVER_SECRET_KEY, b, p).toString();
			byte[] hash = md.digest(sessionString.getBytes("UTF-8"));	
			SESSION_KEY = Arrays.copyOf(hash, 16);
		} catch (Exception e){
			e.printStackTrace();
		}
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
							// Read in the message from the server
							String plainText = "";
							DataInputStream dis = new DataInputStream(socket.getInputStream());
							byte[] serverMessage = new byte[socket.getInputStream().available()];
							dis.readFully(serverMessage);
							System.out.println("Received the following encrypted message from server: ");
							
							// Separate the encrypted message and the mac
							byte[] message = Arrays.copyOf(serverMessage, serverMessage.length-32);	
							System.out.println(bytesToHex(message));
							plainText = AES.decrypt(message, SESSION_KEY, IV);
							System.out.println("Plaintext is: ");
							System.out.println(plainText);
							
							// Confirm the message was received from the correct party
							System.out.println("Verifying integrity of message");
							Mac mac = Mac.getInstance("HmacSHA256");
							SecretKey key = new SecretKeySpec(INTEGRITY_KEY, "HmacSHA256");
					        mac.init(key);
					        byte[] calculatedMac = mac.doFinal(Arrays.copyOfRange(message, message.length-16, message.length));
							byte[] macFromServer = Arrays.copyOfRange(serverMessage, serverMessage.length-32, serverMessage.length);
							System.out.println("The mac received is: \n" + bytesToHex(macFromServer));
							System.out.println("The mac calculated from the message is: \n" + bytesToHex(calculatedMac));
							if (Arrays.equals(macFromServer, calculatedMac)){
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
		};
		
		Thread listener = new Thread(r);
		listener.start();
		
	}
	
	/**
	 * This will send a greeting message and nonce to the server upon initial connection
	 */
	public void sendInitialMessage(){
		String greeting = "HiIAmTheRealClient";
		nonce = DiffieHellman.generateRandomSecretValue();
		DataOutputStream dos;
		try {
			dos = new DataOutputStream(socket.getOutputStream());
			dos.writeUTF(greeting + "~" + nonce.toString());
			System.out.println("Sending the following message to server: " + greeting + "~" + nonce.toString());
			System.out.println("My nonce is: " + nonce.toString());
			System.out.println("Waiting for server's challenge...");
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	public void setHashedKey(byte[] hashedKey) {
		SHARED_KEY = hashedKey;
		computeIntegrityKey();
	}
	
	/**
	 * After receiving the challenge for mutual authentication from the server
	 * process it and send back the response
	 */
	public boolean getChallengeFromServerAndSendResponse(){
		// Get the encrypted text and decrypt it
		String plainText = "";
		String serverNonce = "";
		try{
			// Get the nonce first
			while(socket.getInputStream().available() == 0);
			DataInputStream input = new DataInputStream(socket.getInputStream());
			serverNonce = input.readUTF();
			System.out.println("Server sent the nonce: " + serverNonce);
			
			// Then get the encrypted text
			while(socket.getInputStream().available() == 0);
			DataInputStream dis = new DataInputStream(socket.getInputStream());
			byte[] serverMessage = new byte[socket.getInputStream().available()];
			
			// Decrypt the message appropriately
			dis.readFully(serverMessage);
			System.out.println("The server sent the following encrypted challenge: " + bytesToHex(serverMessage));
			try{
				plainText = AES.decrypt(serverMessage, SHARED_KEY, IV);
			} catch (Exception e){
				System.out.println("You had a different key from the server... failed to decrypt the message");
				return false;
			}
			System.out.println("Plaintext of the challenge is: " + plainText);
		} catch (Exception e){
			e.printStackTrace();
		} 
		
		// Check to make sure the nonce returned was correct
		String myNonceCheck = plainText.split("~")[1];
		SERVER_SECRET_KEY = new BigInteger(plainText.split("~")[2]);
		if (myNonceCheck.equals(nonce.toString())){
			System.out.println("Verified server sent back correct encrypted nonce, successfully authenticated server");
			// If the server authenticated okay, let's let the server authenticate us by sending his nonce back with encryption
			String serverPhrase = plainText.split("~")[0];
			
			// Send a message back that's not the same as the server's
			myPhrase = DiffieHellman.generateRandomSecretValue().toString();
			while (myPhrase.equals(serverPhrase)){
				myPhrase = DiffieHellman.generateRandomSecretValue().toString();
			}
			
			// Send back to the server our response
			System.out.println("Replying the server's challenge...");
			String messageEncryptToServer = myPhrase + "~" + serverNonce + "~" + SECRET_KEY.toString();
			System.out.println("The plaintext challenge response to server is: " + messageEncryptToServer);
			byte[] encryptedMessage;
			try {
				encryptedMessage = AES.encrypt(messageEncryptToServer, SHARED_KEY, IV);
				DataOutputStream output = new DataOutputStream(socket.getOutputStream());
				output.write(encryptedMessage);
				System.out.println("The encrypted challenge response to server is: " + bytesToHex(encryptedMessage));
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
			genSessionKey();
			System.out.println("The shared session key is: " + DiffieHellman.dhMod(SERVER_SECRET_KEY, b, p).toString());
			System.out.println("Waiting for server to authenticate me...");
			return true;
		} else {
			// If the server is fake, get out and close the socket
			System.out.println("That server is a fake! GET OUT!!!!!");
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return false;
		}
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
}
