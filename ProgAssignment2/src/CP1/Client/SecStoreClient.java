package CP1.Client;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class SecStoreClient {
    private static final int PORT = 4321;
    private static final String HOSTNAME = "10.12.24.159";
    private static final String auMessage = "Hello, this is SecStore!";
    private static final String publicKeyFile = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\CP1\\Client\\publicServer.der";
    private static final String CAcert = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\CP1\\Client\\CA.crt";
    private static final String inputFile = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\CP1\\Client\\smallFile.txt";
    private static PublicKey key;

    public static void main(String[] args) throws Exception {

        // Establish connection with SecStore
        Socket echoSocket = new Socket(HOSTNAME, PORT);

        // Establish communication channels with server
        PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
        BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(echoSocket.getInputStream()));

        // Authentication of SecStore's identity
        // Requesting for authentication
        out.println("Hi SecStore! Please prove your identity! The following line is the authentication message.");
        out.println(auMessage);
        System.out.println("Requesting for server authentication...");
        
        // Waiting for signed message by SecStore
        String signedMessage = in.readLine();
        System.out.println("Received signed message from server");
        System.out.println("Signed message: " + signedMessage + "\n");

        // Requesting for public key to verify signed message
        out.println("Give me your certificate signed by CA");

        // Waiting for SecStore to provide signed certificate
        String certBytesSize = in.readLine();
        System.out.println("Received signed certificate from server");
        int certSize = Integer.parseInt(certBytesSize);
        byte[] certBytes = new byte[certSize];
        System.out.println("Certificate size: " + certBytesSize);

        String certBytesStr = in.readLine();
        System.out.println("Certificate bytes: " + certBytesStr);
        certBytes = DatatypeConverter.parseBase64Binary(certBytesStr);

        // Write byte array into file and create X509Certificate object
        FileOutputStream fileOutput = new FileOutputStream(CAcert);
        fileOutput.write(certBytes, 0, certBytes.length);
        fileOutput.close();

        try {
            X509Certificate certificate = CreateX509Cert(CAcert);
            // Extract public key from serverCert
            key = certificate.getPublicKey();
            // Verify that certificate is legitimate
            System.out.println("Verifying signed certificate...");
            if (!Verify(certificate)){
            	// Close connection with server
            	out.close();
                in.close();
                echoSocket.close();
            };
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Decrypting the signed certificate
        System.out.println("\nDecrypting signed certificate...");
        Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        byte[] signedMessageBytes = DatatypeConverter.parseBase64Binary(signedMessage);
        byte[] decryptedCertBytes = dcipher.doFinal(signedMessageBytes);
        String decryptedMessage = new String(decryptedCertBytes, "UTF-16");
        boolean checkResult = decryptedMessage.equals(auMessage);

        System.out.println("Authentication message: " + auMessage);
        System.out.println("Decrypted message: " + decryptedMessage);

        // If check fail
        if (!checkResult) {
            out.println("Check failed! Disconnecting...");
            out.close();
            in.close();
            echoSocket.close();
        }

        // If check succeeded
        else {
            out.println("Signed message is correct.");
            System.out.println("Message verified!");
        }
        
        // Getting ready for file transfer to server
        // Get public key from .der file
        Path keyPath = Paths.get(publicKeyFile);
        byte[] publicKeyBytes = Files.readAllBytes(keyPath);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Create encryption cipher
        Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        ecipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Generate nonce
        byte[] nonce = new byte[32];
        Random rand = SecureRandom.getInstance("SHA1PRNG");
        rand.nextBytes(nonce);
        String nonceString = new String(nonce, "UTF-16"); // this is what we will compare to

        // Send over nonce
        System.out.println("\nSending over nonce");
        out.println(DatatypeConverter.printBase64Binary(nonce));

        // Retrieving the encrypted nonce
        byte[] encryptedNonce = new byte[128];
        String encryptedNonceString = in.readLine();
        encryptedNonce = DatatypeConverter.parseBase64Binary(encryptedNonceString);

        // Decrypting the encrypted nonce and convert it to a String
        byte[] decryptedNonce = dcipher.doFinal(encryptedNonce);
        String decryptedNonceString = new String(decryptedNonce, "UTF-16");

        System.out.println("Nonce String: " + nonceString);
        System.out.println("Decrypted Nonce String: " + decryptedNonceString);

        // Check if decrypted nonce is equal to the original nonce
        boolean checkNonce = decryptedNonceString.equals(nonceString);

        // If check fails
        if (!checkNonce) { // Close connection with server
            System.out.println("Nonce failed to pass");
            out.close();
            in.close();
            echoSocket.close();
        }
        
        System.out.println("Nonce is verified!");
        out.println("Nonce is verified!");
        
        // Authentication protocol done, start file transfer
        System.out.println("\n---FILE TRANSFER---\n" + "Sending over file...");
        out.println("Client is sending over file...");

        // Send time to client for recording duration of file transfer
        out.println(System.currentTimeMillis());

        // Get files (from command line arguments) & bytes for encryption
//        File file = new File(args[0]); // cmd line
        File file = new File(inputFile); // IDE
        byte[] fileBytes = new byte[(int) file.length()];
        BufferedInputStream fileInput;
        try {
            fileInput = new BufferedInputStream(new FileInputStream(file));
            fileInput.read(fileBytes, 0, fileBytes.length);
            fileInput.close();
        } catch (FileNotFoundException e) {
            System.out.println("File not found. Program terminating...");
            out.close();
            in.close();
            echoSocket.close();
        }

        // Encrypt file
        byte[] encryptedFileBytes = encryptFile(fileBytes, ecipher);

        // Send over file name (Change depending on IDE/cmdline)
//        out.println(args[0]); // cmd line
        out.println(inputFile); // IDE

        // Send filesize in bytes to server
        out.println(encryptedFileBytes.length);

        // Send byteString to server
        out.println(DatatypeConverter.printBase64Binary(encryptedFileBytes));
//
        // Wait for server to send signal of upload completion
        String serverResponse = in.readLine();
        if (serverResponse.equals("Upload completed")) {
            System.out.println("File transfer complete");
            out.println("File transfer complete");
        } else {
            System.out.println("File upload failed");
        }
        
        // Notify server to close connection
        out.close();
        in.close();
        echoSocket.close();
    }

    public static X509Certificate CreateX509Cert(String cert) throws CertificateException, FileNotFoundException {
        InputStream fis = new FileInputStream(cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate X509cert = (X509Certificate) cf.generateCertificate(fis);
        return X509cert;
    }

    public static boolean Verify(X509Certificate signedCert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            signedCert.checkValidity();
            System.out.println("Certificate verified!");
            return true;
        } catch (Exception e) {
            System.out.println("Certificate verification failed!");
            return false;
        }
    }

    public static byte[] encryptFile(byte[] fileBytes, Cipher ecipher) throws Exception {
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        int start = 0;
        int fileLength = fileBytes.length;
        while (start < fileLength) {
            byte[] tempBuff;
            // 117 bytes is the encryption limit for a 1024-bit RSA key
            if (fileLength - start >= 117) {
                tempBuff = ecipher.doFinal(fileBytes, start, 117);
            } else {
                tempBuff = ecipher.doFinal(fileBytes, start, fileLength - start);
            }
            byteOutput.write(tempBuff, 0, tempBuff.length);
            start += 117;
        }
        byte[] encryptedFileBytes = byteOutput.toByteArray();
        byteOutput.close();
        return encryptedFileBytes;

    }

}
