

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

public class Client {

	private Socket socket;
	private BigInteger b;
	private BigInteger p;
	private BigInteger g;
	private BigInteger SECRET_KEY;
	
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
	
	public void establishDiffieHellman(){
		Runnable r = new Runnable(){
			public void run () {
				try{
					while (true){
						if (socket.getInputStream().available() != 0){
							DataInputStream input = new DataInputStream(socket.getInputStream());
							System.out.println(input.readUTF());
							establishSessionKey(input.readUTF());
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
	
	private void establishSessionKey(String readUTF) {
		System.out.println("Establishing session key...");
		String[] splitReadUTF = readUTF.split("~");
		try {
			scrapeGValue(splitReadUTF);
			scrapePValue(splitReadUTF);
		} catch (Exception e) {
			System.err.println("Bad G value: " + g.toString());
			System.err.println("Bag P Value: " + p.toString());
			e.printStackTrace();
		}
		genSecretKey();
	}
	
	private void scrapeGValue(String[] readUTF) throws Exception {
		String gValue = readUTF[1]; //hardcode
		if(!gValue.matches("[0-9]*")){
			throw new Exception("unexpected G value");
		}
		
		g = new BigInteger(gValue);
	}
	
	private void scrapePValue(String[] readUTF) throws Exception {
		String pValue = readUTF[3]; //hardcode
		if(!pValue.matches("[0-9]*")){
			throw new Exception("unexpected P value");
		}
		
		p = new BigInteger(pValue);
	}
	
	private void genSecretKey() {
		b = DiffieHellman.generateRandomSecretValue();
	}
	
	private void initSecretKey() {
		SECRET_KEY = DiffieHellman.dhMod(g, b, p);
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
