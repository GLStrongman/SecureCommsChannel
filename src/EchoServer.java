import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

	private ServerSocket serverSocket;
	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	public PublicKey getClientKey(){
		// Create and initialize keypair
		try {
			System.out.println("Please enter the client's public key: ");
			Scanner sc = new Scanner(System.in);
			String clientKey = sc.next();

			Base64.Decoder decoder = Base64.getDecoder();
			byte[] clientPubKeyByte = decoder.decode(clientKey);

			X509EncodedKeySpec clientPubKeySpec = new X509EncodedKeySpec(clientPubKeyByte);
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			return keyFac.generatePublic(clientPubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}


	/**
	 * Create the server socket and wait for a connection.
	 * Keep receiving messages until the input stream is closed by the client.
	 *
	 * @param port the port number of the server
	 */
	public void start(int port) {
		try {
			String encCipherName = "RSA/ECB/PKCS1Padding";
			String signCipherName = "SHA256withRSA";

			serverSocket = new ServerSocket(port);
			clientSocket = serverSocket.accept();
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
			byte[] data = new byte[256];

			PublicKey clientPubKey = getClientKey();

			KeyPairGenerator keyGen = null;
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair serverKey = keyGen.generateKeyPair();
			Base64.Encoder encoder = Base64.getEncoder();
			System.out.println("Sever public key: " + encoder.encode(serverKey.getPublic().getEncoded()));

			int numBytes;
			while ((numBytes = in.read(data)) != -1) {
				Cipher cipher = Cipher.getInstance(encCipherName);
				cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());

				// decrypt data
				byte[] decryptedBytes = cipher.doFinal(data);
				String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
				System.out.println("Server received cleartext " + decryptedString);

				cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
				final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
				byte[] cipherTextBytes = cipher.doFinal(originalBytes);

				// encrypt response (this is just the decrypted data re-encrypted)
				System.out.println("Server sending ciphertext " + cipherTextBytes);
				out.write(cipherTextBytes);
				out.flush();
			}
			stop();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Close the streams and sockets.
	 *
	 */
	public void stop() {
		try {
			in.close();
			out.close();
			clientSocket.close();
			serverSocket.close();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}

	}

	public static void main(String[] args) {
		EchoServer server = new EchoServer();
		server.start(4444);
	}

}
