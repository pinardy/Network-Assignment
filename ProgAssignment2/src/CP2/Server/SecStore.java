package CP2.Server;

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;

public class SecStore {
	private static final int PORT = 4321;
	private static final String privateKeyFile = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\CP2\\Server\\privateServer.der";
	private static final String myCert = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\CP2\\Server\\other.crt";


	public static void main(String[] args) throws Exception {
		// Establish server connection
		ServerSocket serverSocket = new ServerSocket(PORT);
		
		System.out.println("Server started");

		// Retrieve private key from privateServer.der file to sign message
		Path path = Paths.get(privateKeyFile);
		byte[] privateKeyBytes = Files.readAllBytes(path);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey myPrivateKey = keyFactory.generatePrivate(keySpec);

		// Create and initialize encryption cipher
		Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		ecipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);

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
			System.out.println("Client: " + in.readLine());

			// Retrieve authentication message and sign message before sending to client
			String auMessage = in.readLine();
			System.out.println("Authentication message: " + auMessage);
			while (true){
			    String serverInput = serverIn.readLine();
			    if (serverInput.equals(auMessage)) {
                    break;
                } else {
                    System.out.println("Authentication message did not match. Please try again!");
                }
            }
			
			byte[] signedMessageBytes = ecipher.doFinal(auMessage.getBytes("UTF-16"));
			String signedMessage = DatatypeConverter.printBase64Binary(signedMessageBytes);

			// Send signed message to client
			out.println(signedMessage);
			System.out.println("Sent signed message to client.");

			// Waiting for client to make request
			System.out.println("Client: " + in.readLine());

			// Send signed certificate to the client
			out.println(certBytes.length);
			out.println(certStr);
			System.out.println("Sent signed certificate to client.");
			
//			// Wait for client's response
			System.out.println("Client: " + in.readLine()); 

			// Wait for client to send nonce
            String nonceString = in.readLine();
            byte[] nonce = new byte[32];
            nonce = DatatypeConverter.parseBase64Binary(nonceString);

			// Encrypt nonce
            byte[] encryptedNonce = ecipher.doFinal(nonce);
            out.println(DatatypeConverter.printBase64Binary(encryptedNonce));
            
            // Wait for client response
            System.out.println("Client: " + in.readLine());
            
            // Symmetric key crypto for confidentiality protocol
            // Wait for client to send size of encrypted session key and the encrypted session key itself
            int keySize = Integer.parseInt(in.readLine());
            byte[] encryptedKey = new byte[keySize];
            encryptedKey = DatatypeConverter.parseBase64Binary(in.readLine());
            
            // Get decryption cipher with private RSA key
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
            byte[] decryptedKey = dcipher.doFinal(encryptedKey);
            SecretKey sessionKey = new SecretKeySpec(decryptedKey, 0 , decryptedKey.length, "AES");
           
            // Create and initialize AES cipher with session key
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE,sessionKey);
            
            // Authentication protocol done, starting file transfer
            System.out.println("\n---FILE TRANSFER---");
            
            String clientMessage = in.readLine();
            System.out.println(clientMessage);
            while (clientMessage.equals("Client is sending over file...")){
                // Client sends over file upload start time
                long startTime = Long.parseLong(in.readLine());

                // Client sends over file name
                String fileName = in.readLine();

                // Client sends filesize in bytes over
                int fileSize = Integer.parseInt(in.readLine());
                System.out.println("File size: " + fileSize + " bytes");
                byte[] encryptedBytes = new byte[fileSize];

                // Receives byteString
                String byteString = in.readLine();
                encryptedBytes = DatatypeConverter.parseBase64Binary(byteString);

                // Decrypt file in blocks of 128 bytes
                byte[] decryptedFileBytes = aesCipher.doFinal(encryptedBytes);

                // Write to file
//                FileOutputStream fileOutput = new FileOutputStream("testOutput.txt"); // for testing
                FileOutputStream fileOutput = new FileOutputStream(fileName);
                fileOutput.write(decryptedFileBytes, 0, decryptedFileBytes.length);
                fileOutput.close();

                // Display upload duration
                System.out.println("\nFile transfer complete!");
                System.out.println("Time taken: " + (System.currentTimeMillis() - startTime) + " milliseconds for " + fileName + " to be uploaded.");
                out.println("Upload completed");

                // Check client message
                clientMessage = in.readLine();
            }
            
            in.close();
            out.close();

		} catch (Exception e){
		}

		certInput.close();
		serverSocket.close();
	}
}
