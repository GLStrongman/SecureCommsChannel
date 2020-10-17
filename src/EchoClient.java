import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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

	private String SigCipherName = "SHA256withRSA";
	private String EncCipherName = "RSA/ECB/PKCS1Padding";

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
			//e.printStackTrace();
			System.out.println("Error: this encryption algorithm doesn't exist.");
			return null;
		}
	}

	public PublicKey getServerKey() {
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
			//e.printStackTrace();
			System.out.println("Error: this encryption algorithm doesn't exist.");
			return null;
		} catch (InvalidKeySpecException e) {
			//e.printStackTrace();
			System.out.println("Error: this key spec is invalid.");
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

			Cipher cipher = Cipher.getInstance(EncCipherName);
			Base64.Encoder encoder = Base64.getEncoder();
			System.out.println("Client sending cleartext " + msg);
			byte[] encryptedBytes = msg.getBytes(StandardCharsets.UTF_8);

			// Encrypt data
			cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			byte[] cipherTextBytes = cipher.doFinal(encryptedBytes);

			// Sign data
			Signature sig = Signature.getInstance(SigCipherName);
			sig.initSign(clientKey.getPrivate());
			sig.update(encryptedBytes);
			byte[] signatureBytes = sig.sign();

			System.out.println("Client sending ciphertext " + new String(encoder.encode(cipherTextBytes)));
			//System.out.println("Client sending signature " + new String(encoder.encode(signatureBytes)));

			out.write(cipherTextBytes);
			out.write(signatureBytes);
			out.flush();
			byte[] inMessage = new byte[256];
			byte[] inSignature = new byte[256];
			in.read(inMessage);
			in.read(inSignature);

			cipher.init(Cipher.DECRYPT_MODE, clientKey.getPrivate());

			// Decrypt data
			byte[] decryptedBytes = cipher.doFinal(inMessage);
			String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
			System.out.println("Server returned cleartext " + decryptedString);

			// Authenticate signature
			System.out.println("Checking signature...");
			sig.initVerify(serverPubKey);
			sig.update(decryptedBytes);

			final boolean signatureValid = sig.verify(inSignature);
			if (signatureValid) {
				System.out.println("Server signature is valid");
			} else {
				throw new IllegalArgumentException("Signature does not match");
			}

			return decryptedString;

		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Error: problem with file reading/writing. ");
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error: the given algorithm is invalid. ");
			return null;
		} catch (InvalidKeyException e) {
			System.out.println("Error: the given key is invalid. ");
			return null;
		} catch (SignatureException e) {
			System.out.println("Error: problem with signature. ");
			return null;
		} catch (NoSuchPaddingException | BadPaddingException e) {
			System.out.println("Error: problem with the encryption algorithm padding. ");
			return null;
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error: block size is invalid. ");
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
			System.out.println("Error when closing.");
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
