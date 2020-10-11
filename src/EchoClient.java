import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class EchoClient {

	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	/**
	 * Setup the two way streams.
	 *
	 * @param ip the address of the server
	 * @param port port used by the server
	 *
	 */
	public void startConnection(String ip, int port) {
		try {
			clientSocket = new Socket(ip, port);
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
		} catch (IOException e) {
			System.out.println("Error when initializing connection");
		}
	}

	public void generateKey() {
		try {
			String encCipherName = "RSA/ECB/PKCS1Padding";
			String signCipherName = "SHA256withRSA";
			// Create and initialize keypair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair serverKey = keyGen.generateKeyPair();
			System.out.println("Sever public key: " + serverKey.getPublic().toString());
			Cipher cipher = Cipher.getInstance(encCipherName);
			cipher.init(Cipher.ENCRYPT_MODE, serverKey.getPublic());
		}
		catch(Exception e) {

		}
	}

	/**
	 * Send a message to server and receive a reply.
	 *
	 * @param msg the message to send
	 */
	public String sendMessage(String msg) {
		try {
			System.out.println("Client sending cleartext "+msg);
			byte[] data = msg.getBytes("UTF-8");
			// encrypt data
			System.out.println("Client sending ciphertext "+Util.bytesToHex(data));
			out.write(data);
			out.flush();
			in.read(data);
			// decrypt data
			String reply = new String(data, "UTF-8");
			System.out.println("Server returned cleartext "+reply);
			return reply;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}

	/**
	 * Close down our streams.
	 *
	 */
	public void stopConnection() {
		try {
			in.close();
			out.close();
			clientSocket.close();
		} catch (IOException e) {
			System.out.println("error when closing");
		}
	}

	public static void main(String[] args) {
		EchoClient client = new EchoClient();
		client.generateKey();
		client.startConnection("127.0.0.1", 4444);
		client.sendMessage("12345678");
		client.sendMessage("ABCDEFGH");
		client.sendMessage("87654321");
		client.sendMessage("HGFEDCBA");
		client.stopConnection();
	}
}
