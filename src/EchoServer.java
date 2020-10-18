import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

	private String EncCipherName = "RSA/ECB/PKCS1Padding";
	private String SigCipherName = "SHA256withRSA";

	private ServerSocket serverSocket;
	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	private Key masterKey = null;
	private byte[] AADTag = "auth".getBytes();

	public void getMasterKey(DataInputStream in, DataOutputStream out, String location, String password, byte[] key) {
		try {
			byte[] inSignature = new byte[256];

			// Get keys from keystore
			KeyStore keyStore = KeyStore.getInstance("JKS");
			char[] keyStorePassword = "badpassword".toCharArray();
			try(InputStream keyStoreData = new FileInputStream(location)){
				keyStore.load(keyStoreData, keyStorePassword);
			} catch (CertificateException e) {
				System.out.println("Error: couldn't load key store.");
			}
			char[] keyPassword = password.toCharArray();

			PublicKey clientPubKey = keyStore.getCertificate("client").getPublicKey();
			Key serverKeyEntry = keyStore.getKey("server", keyPassword);
			PrivateKey serverKey = (PrivateKey)serverKeyEntry;

			Cipher cipher = Cipher.getInstance(EncCipherName);
			Signature sig = Signature.getInstance(SigCipherName);
			Base64.Encoder encoder = Base64.getEncoder();

			in.read(inSignature);
			cipher.init(Cipher.DECRYPT_MODE, serverKey);
			// Decrypt data
			byte[] decryptedBytes = cipher.doFinal(key);
			String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
			System.out.println("Server master key " + masterKey);

			// Authenticate signature
			System.out.println("Checking signature...");
			sig.initVerify(clientPubKey);
			sig.update(decryptedBytes);

			final boolean signatureValid = sig.verify(inSignature);
			if (signatureValid) {
				System.out.println("Client signature is valid");
			} else {
				throw new IllegalArgumentException("Signature does not match");
			}

			masterKey = new SecretKeySpec(decryptedBytes, "AES");

			// Encrypt data
			cipher.init(Cipher.ENCRYPT_MODE, clientPubKey);
			final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
			byte[] cipherTextBytes = cipher.doFinal(originalBytes);

			// Sign data
			sig.initSign(serverKey);
			sig.update(originalBytes);
			byte[] signatureBytes = sig.sign();

			// Encrypt response (this is just the decrypted data re-encrypted)
			System.out.println("Server returning master key " + new String(encoder.encode(masterKey.getEncoded())));

			out.write(cipherTextBytes);
			out.write(signatureBytes);
			out.flush();
		} catch (IOException e) {
			System.out.println("Error: problem with file reading/writing - is the file location correct? ");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error: the given algorithm is invalid. ");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.out.println("Error: the given key is invalid. ");
		} catch (SignatureException e) {
			System.out.println("Error: problem with signature. ");
		} catch (NoSuchPaddingException | BadPaddingException e) {
			System.out.println("Error: problem with the encryption algorithm padding. ");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error: block size is invalid. ");
		} catch (KeyStoreException e) {
			System.out.println("Error: this keystore type is invalid. ");
		} catch (UnrecoverableEntryException e) {
			System.out.println("Error: could not get key from keystore");
		}
	}

	/**
	 * Create the server socket and wait for a connection.
	 * Keep receiving messages until the input stream is closed by the client.
	 *
	 * @param port the port number of the server
	 */
	public void start(int port, String password, String location) {
		try {
			System.out.println("Waiting for client...");

			serverSocket = new ServerSocket(port);
			clientSocket = serverSocket.accept();
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
			byte[] data = new byte[256];
			byte[] nonce = new byte[16];

			Cipher symCipher = Cipher.getInstance("AES/GCM/NoPadding");
			Base64.Encoder encoder = Base64.getEncoder();

				int numBytes;
				while ((numBytes = in.read(data)) != -1) {
					if (masterKey == null){
						getMasterKey(in, out, location, password, data);
					}
					else {
						byte[] dataTrunc = Arrays.copyOfRange(data, 0, 36);

						in.read(nonce);

						GCMParameterSpec gcm = new GCMParameterSpec(128, nonce);

						// Decrypt data
						symCipher.init(Cipher.DECRYPT_MODE, masterKey, gcm);
						symCipher.updateAAD(AADTag);
						byte[] decryptedBytes = symCipher.doFinal(dataTrunc);
						String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
						System.out.println("Server received cleartext " + decryptedString);

						// Encrypt data
						symCipher.init(Cipher.ENCRYPT_MODE, masterKey, gcm);
						symCipher.updateAAD(AADTag);
						final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
						byte[] cipherTextBytes = symCipher.doFinal(originalBytes);

						// Encrypt response (this is just the decrypted data re-encrypted)
						System.out.println("Server sending ciphertext " + new String(encoder.encode(cipherTextBytes)));

						out.write(cipherTextBytes);
						out.write(nonce);
						out.flush();
					}
				}
			stop();
		} catch (IOException e) {
			System.out.println("Error: problem with file reading/writing - is the file location correct? ");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error: the given algorithm is invalid. ");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.out.println("Error: the given key is invalid. ");
		} catch (NoSuchPaddingException | BadPaddingException e) {
			System.out.println("Error: problem with the encryption algorithm padding. ");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error: block size is invalid. ");
		} catch (InvalidAlgorithmParameterException e) {
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
			System.out.println("Error while closing server.");
		}

	}

	public static void main(String[] args) {
		EchoServer server = new EchoServer();
		if (args.length != 2){
			System.out.print("Incorrect arguments - please enter server key password and file store location.");
		} else {
			server.start(4444, args[0], args[1]);
		}
	}
}
