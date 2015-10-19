

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Scanner;

public class Client {

	private Socket socket;
	private BigInteger b;
	private BigInteger p;
	private BigInteger g;
	private BigInteger SERVER_SECRET_KEY;
	private BigInteger SESSION_KEY;
	private BigInteger SECRET_KEY;
	private byte[] SHARED_KEY;
	
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
	
	public void sendMessage(){
		Scanner reader = new Scanner(System.in);
		try {
			while (true){
				String message = reader.nextLine();
				DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
				dos.writeUTF(message);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * 	Listen to the server for the g and p values. Then send the client's Diffie-hellman value to the server.
	 * 	Also save the session key. 	
	 */
	public void getDiffieHellmanValues(){
		try{
			if (socket.getInputStream().available() != 0){
				DataInputStream input = new DataInputStream(socket.getInputStream());
				String serverMessage = input.readUTF();
				System.out.println(serverMessage);
				scrapeGValue(serverMessage);
				scrapePValue(serverMessage);
				createSecretKey();
			}
		} catch (IOException e){
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Client will create the secret key. 
	 */
	private void createSecretKey() {
		genSecretValue(); //little b
		initSecretKey();
		System.out.println("Client Secret key: ~" + SECRET_KEY.toString() + "~");
	}
	
//	private void establishSessionKey(String readUTF) {
//		System.out.println("Establishing session key...");
//		String[] splitReadUTF = readUTF.split("~");
//		try {
//			scrapeGValue(splitReadUTF);
//			scrapePValue(splitReadUTF);
//			scrapeServerDHValue(splitReadUTF);
//		} catch (Exception e) {
//			System.err.println("Bad G value: " + g.toString());
//			System.err.println("Bag P Value: " + p.toString());
//			e.printStackTrace();
//		}
//		genSecretValue();
//		initSecretKey();
//		genSessionKey();
//	}
	
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
	
	private void scrapeServerDHValue(String readUTF) throws Exception {
		String pValue = readUTF.split("~")[5]; //hardcode
		if(!pValue.matches("[0-9]*")){
			throw new Exception("unexpected P value");
		}
		
		SERVER_SECRET_KEY = new BigInteger(pValue);
	}
	
	private void genSecretValue() {
		b = DiffieHellman.generateRandomSecretValue();
	}
	
	private void initSecretKey() {
		SECRET_KEY = DiffieHellman.dhMod(g, b, p);
	}
	
	private void genSessionKey() {
		SESSION_KEY = DiffieHellman.dhMod(SERVER_SECRET_KEY, b, p);
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
	
	/**
	 * This will send a greeting message and nonce to the server upon initial connection
	 */
	public void sendInitialMessage(){
		String greeting = "HiIAmTheRealClient";
		BigInteger nonce = DiffieHellman.generateRandomSecretValue();
		DataOutputStream dos;
		try {
			dos = new DataOutputStream(socket.getOutputStream());
			dos.writeUTF(greeting + "~" + nonce.toString());
			System.out.println("My nonce is: " + nonce.toString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void setHashedKey(byte[] hashedKey) {
		SHARED_KEY = hashedKey;
	}
	
	public void getChallengeFromServerAndSendResponse(){
		try{
			while(socket.getInputStream().available() == 0);
			DataInputStream input = new DataInputStream(socket.getInputStream());
			byte[] serverMessage = new byte[2048];
			input.readFully(serverMessage);
			System.out.println("Encrypted message from server is: " + serverMessage);
			String plaintext = AES.decrypt(serverMessage, SHARED_KEY);
			System.out.println("Plaintext is: " + plaintext);
		} catch (Exception e){
			e.printStackTrace();
		} 
	}
	
}
