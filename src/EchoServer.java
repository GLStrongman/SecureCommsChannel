import java.net.*;
import java.io.*;

public class EchoServer {

	private ServerSocket serverSocket;
	private Socket clientSocket;
	private DataOutputStream out;
	private DataInputStream in;

	/**
	 * Create the server socket and wait for a connection.
	 * Keep receiving messages until the input stream is closed by the client.
	 *
	 * @param port the port number of the server
	 */
	public void start(int port) {
		try {
			serverSocket = new ServerSocket(port);
			clientSocket = serverSocket.accept();
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
			byte[] data = new byte[8];
			int numBytes;
			while ((numBytes = in.read(data)) != -1) {
				// decrypt data
				String msg = new String(data, "UTF-8");
				System.out.println("Server received cleartext "+msg);
				// encrypt response (this is just the decrypted data re-encrypted)
				System.out.println("Server sending ciphertext "+Util.bytesToHex(data));
				out.write(data);
				out.flush();
			}
			stop();
		} catch (IOException e) {
			System.out.println(e.getMessage());
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
