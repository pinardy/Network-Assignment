package Server;


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
	private static final String privateKeyFile = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Server\\privateServer.der";
	private static final String myCert = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Server\\1001520.crt";


	public static void main(String[] args) throws Exception {
		System.out.println("Server started");

		// Establish server connection
		ServerSocket serverSocket = new ServerSocket(PORT);

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
			System.out.println(in.readLine());

			// Retrieve authentication message and sign message before sending to client
			String auMessage = serverIn.readLine();
			byte[] signedMessageBytes = ecipher.doFinal(auMessage.getBytes("UTF-16"));
			String signedMessage = DatatypeConverter.printBase64Binary(signedMessageBytes);

			// send signed message to client
			out.println(signedMessage);
			System.out.println("Sent signed message to client.");

			// Waiting for client to make request
			System.out.println(in.readLine());

			// Send signed certificate to the client
			out.println(certBytes.length);
			out.println(certStr);
			System.out.println("Sent signed certificate to client.");
			
//			// Wait for client's response for cert request
			String msg = in.readLine();
			System.out.println(msg); // should say "Signed message is correct."

			//TODO: Wait for nonce
            String nonceString = in.readLine();
            System.out.println(nonceString);
            byte[] nonce = new byte[32];
            nonce = DatatypeConverter.parseBase64Binary(nonceString);

			//TODO: Encrypt nonce
            byte[] encryptedNonce = ecipher.doFinal(nonce);
            out.println(DatatypeConverter.printBase64Binary(encryptedNonce));

            //TODO: Get decryption cipher with private RSA key
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, myPrivateKey);

            // client sends its intention to start transfer
            String clientMessage = in.readLine();
            while(clientMessage.equals("Client is sending over file...")){
                //TODO: client sends over upload start time
                long startTime = Long.parseLong(in.readLine());

                //TODO: client sends over file name
                String filename = in.readLine();

                //TODO: client sends filesize in bytes over
                int fileSize = Integer.parseInt(in.readLine());
                System.out.println("File size " + fileSize);
                byte[] encryptedBytes = new byte[fileSize];
                String byteString = in.readLine();
                encryptedBytes = DatatypeConverter.parseBase64Binary(byteString);

                //TODO: Decrypt file in blocks of 128 bytes
                byte[] decryptedFileBytes = decryptFile(encryptedBytes, dcipher);

                //TODO: Write to file
//                FileOutputStream fileOutput = new FileOutputStream(filename);
                FileOutputStream fileOutput = new FileOutputStream("C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Server\\smallFile.txt");
                fileOutput.write(decryptedFileBytes, 0, decryptedFileBytes.length);
                fileOutput.close();

                //TODO: Display upload duration
                System.out.println("Time taken: " + (System.currentTimeMillis() - startTime) + " milliseconds for " + filename + " to be uploaded.");

                //TODO: Check client message
                clientMessage = in.readLine();
            }
            in.close();
            out.close();

		} catch (Exception e){
			e.printStackTrace();
		}

		certInput.close();
		serverSocket.close();
	}

    public static byte[] decryptFile(byte[] encryptedData, Cipher dcipher) throws Exception{
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        int start = 0;
        int fileSize = encryptedData.length;
        while (start < fileSize) {
            //System.out.println("Start: " + start);
            byte[] tempBuff;
            if (fileSize - start >= 128) {
                tempBuff = dcipher.doFinal(encryptedData, start, 128);
            } else {
                tempBuff = dcipher.doFinal(encryptedData, start, fileSize - start);
            }
            byteOutput.write(tempBuff, 0, tempBuff.length);
            start += 128;
        }
        byte[] decryptedFileBytes = byteOutput.toByteArray();
        byteOutput.close();
        return decryptedFileBytes;


    }
}
