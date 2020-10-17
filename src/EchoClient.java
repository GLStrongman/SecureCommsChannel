import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

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

	public KeyPair generateKey() {
		try {
			// Create and initialize keypair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair clientKey = keyGen.generateKeyPair();
			Base64.Encoder encoder = Base64.getEncoder();
			System.out.println("Client public key: " + new String(encoder.encode(clientKey.getPublic().getEncoded())));
			return clientKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public PublicKey getServerKey(){
		// Create and initialize keypair
		try {
			System.out.println("Please enter the server's public key: ");
			Scanner sc = new Scanner(System.in);
			String serverKey = sc.next();

			Base64.Decoder decoder = Base64.getDecoder();
			byte[] serverPubKeyByte = decoder.decode(serverKey);

			X509EncodedKeySpec serverPubKeySpec = new X509EncodedKeySpec(serverPubKeyByte);
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			return keyFac.generatePublic(serverPubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Send a message to server and receive a reply.
	 *
	 * @param msg the message to send
	 */
	public String sendMessage(String msg, PublicKey serverPubKey, KeyPair clientKey) {
		try {
			String encCipherName = "RSA/ECB/PKCS1Padding";
			String signCipherName = "SHA256withRSA";
			Cipher cipher = Cipher.getInstance(encCipherName);
			//cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			Base64.Encoder encoder = Base64.getEncoder();

			System.out.println("Client sending cleartext " + msg);
			byte[] data = msg.getBytes("UTF-8");

			// encrypt data
			cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			final byte[] encryptedBytes = data;
			byte[] cipherTextBytes = cipher.doFinal(encryptedBytes);
			System.out.println("Client sending ciphertext " + new String(encoder.encode(cipherTextBytes))); //TODO - wrong?

			out.write(cipherTextBytes);
			out.flush();
			in.read(data);

			cipher.init(Cipher.DECRYPT_MODE, clientKey.getPrivate());

			// decrypt data
			byte[] decryptedBytes = cipher.doFinal(data);
			String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
			System.out.println("Server returned cleartext " + decryptedString);
			return decryptedString;

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
		client.startConnection("127.0.0.1", 4444);
		KeyPair clientKey = client.generateKey();
		PublicKey serverPubKey = client.getServerKey();
		client.sendMessage("12345678", serverPubKey, clientKey);
		client.sendMessage("ABCDEFGH", serverPubKey, clientKey);
		client.sendMessage("87654321", serverPubKey, clientKey);
		client.sendMessage("HGFEDCBA", serverPubKey, clientKey);
		client.stopConnection();
	}
}
