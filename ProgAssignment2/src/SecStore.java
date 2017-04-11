package ProgAssignment2.src;


import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import java.io.*;

public class SecStore {
	private static final int PORT = 4321;
	private static final String privateKeyFile = "privateServer.der";
	private static final String myCert = "1001520.crt";


	public static void main(String[] args) throws Exception {
		// Establish server connection
		ServerSocket serverSocket = new ServerSocket(PORT);

		// Retrieve private key from privateServer.der file to sign message
		Path path = Paths.get(privateKeyFile);
		byte[] privateKeyBytes = Files.readAllBytes(path);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey myPrivateKey = keyFactory.generatePrivate(keySpec);

		// Create and initialize encryption cipher
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);

		// Prepare signed certificate required for authentication
		File cert = new File(myCert);
		byte[] certBytes = new byte[(int) (cert.length())];
		BufferedInputStream certInput = new BufferedInputStream(new FileInputStream(cert));
		certInput.read(certBytes,0,certBytes.length);
		String certStr = DatatypeConverter.printBase64Binary(certBytes);


		try {
			// Waiting for client to initialize connection
			Socket clientSocket = serverSocket.accept();
			System.out.println("Client connected...");
			PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);
			BufferedReader in = new BufferedReader(
					new InputStreamReader(clientSocket.getInputStream()));
			BufferedReader serverIn = new BufferedReader(
					new InputStreamReader(System.in));
			
			// Waiting for client to make request
			System.out.println(in.readLine());

			// Retrieve authentication message and sign message before sending to client
			String auMessage = serverIn.readLine();
			byte[] signedMessageBytes = cipher.doFinal(auMessage.getBytes("UTF-16"));
			String signedMessage = DatatypeConverter.printBase64Binary(signedMessageBytes);
			out.println(signedMessage);
			System.out.println("Sent signed message to client.");

			// Waiting for client to make request
			System.out.println(in.readLine());

			// Send signed certificate to the client
			out.println(certBytes.length);
			out.println(certStr);
			System.out.println("Sent signed certificate to client.");
			
			// Wait for client's response


		} catch (Exception e){
			e.printStackTrace();
		}

		certInput.close();
		serverSocket.close();
	}

}
