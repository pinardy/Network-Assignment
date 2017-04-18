package Client;


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
    private static final String HOSTNAME = "localhost";
    private static final String publicKeyFile = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Client\\publicServer.der";
    private static final String auMessage = "Hello, this is SecStore!";
    private static final String serverCertStr = "serverCert.crt";
    private static final String CACERT = "C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Client\\CA.crt";
    private static PublicKey key;

    public static void main(String[] args) throws Exception {

        // Establish connection with SecStore
        Socket echoSocket = new Socket();
        SocketAddress sockaddr = new InetSocketAddress(HOSTNAME, PORT);
        echoSocket.connect(sockaddr, 100);

        // Establish communication channels with server
        PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
        BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(echoSocket.getInputStream()));

        // File to be uploaded to the server
//        BufferedReader br = new BufferedReader(new FileReader("1001520.crt"));

        // Authentication of SecStore's identity

        // Requesting for authentication
        out.println("Hi SecStore! Please prove your identity! Authentication Message: " + auMessage);

        // Waiting for signed message by SecStore
        String signedMessage = in.readLine();
        System.out.println("Signed message: " + signedMessage);

        // Requesting for public key to verify signed message
        out.println("Give me your certificate signed by CA");

        // Waiting for SecStore to provide signed certificate
        String certBytesSize = in.readLine();
        int certSize = Integer.parseInt(certBytesSize);
        byte[] certBytes = new byte[certSize];
        System.out.println("Certificate size: " + certBytesSize);

        String certBytesStr = in.readLine();
        System.out.println("Certificate bytes: " + certBytesStr);
        certBytes = DatatypeConverter.parseBase64Binary(certBytesStr);

        // Retrieve signed certificate by creating X509Certificate object
        FileOutputStream serverCertOutput = new FileOutputStream(serverCertStr);
        serverCertOutput.write(certBytes, 0, certBytes.length);

        //-=-=-=-=- ADDED PART =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        // Write byte array into file and create X509Certificate object
        FileOutputStream fileOutput = new FileOutputStream("CA.crt");
        fileOutput.write(certBytes, 0, certBytes.length);

//        FileInputStream certFileInput = new FileInputStream("CA.crt");
        //-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


        try {
            X509Certificate certificate = CreateX509Cert("CA.crt");

//            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            X509Certificate certificate = (X509Certificate) cf.generateCertificate(certFileInput);

            // Extract public key from serverCert
            key = certificate.getPublicKey();
            // Verify that certificate is legitimate
            Verify(certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Decrypting the signed certificate
        System.out.println("Decrypting the signed certificate...");
        Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        byte[] signedMessageBytes = DatatypeConverter.parseBase64Binary(signedMessage);
        byte[] decryptedCertBytes = dcipher.doFinal(signedMessageBytes);
        String decryptedMessage = new String(decryptedCertBytes, "UTF-16");
        boolean checkResult = decryptedMessage.equals(auMessage);

        System.out.println("Signed message: " + signedMessage);
        System.out.println("Decrypted message: " + decryptedMessage);

        // If check fail
        if (!checkResult) {
            out.println("Check failed! Disconnecting...");
            out.close();
            in.close();
            echoSocket.close();
//        	br.close();
        }

        // If check succeeded
        else {
            out.println("Signed message is correct.");
        }

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


        // Check nonce
        // getting the encrypted nonce
        byte[] encryptedNonce = new byte[128];
        String encryptedNonceString = in.readLine();
        encryptedNonce = DatatypeConverter.parseBase64Binary(encryptedNonceString);

        // decrypting the encrypted nonce and convert to a String
        byte[] decryptedNonce = dcipher.doFinal(encryptedNonce);
        String decryptedNonceString = new String(decryptedNonce, "UTF-16");

        System.out.println("Nonce String: " + nonceString);
        System.out.println("Decrypted Nonce String: " + decryptedNonceString);

        // check if decrypted nonce is equal to the original nonce
        boolean checkNonce = decryptedNonceString.equals(nonceString);

        if (!checkNonce) { // close connection
            System.out.println("Nonce failed to pass");
            out.close();
            in.close();
            echoSocket.close();
//            return;
        }

        System.out.println("\n---FILE TRANSFER---\n" + "Sending over file...");
        out.println("Client is sending over file...");

        // send time to client for recording duration of file transfer
        out.println(System.currentTimeMillis());

        //TODO: Get files (from command line arguments) & bytes for encryption
//        File file = new File(args[0]); // cmd line
        File file = new File("C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\Network-Assignment\\ProgAssignment2\\src\\Client\\largeFile.txt"); // IDE
        byte[] fileBytes = new byte[(int) file.length()];
        BufferedInputStream fileInput = new BufferedInputStream(new FileInputStream(file));
        fileInput.read(fileBytes, 0, fileBytes.length);

        fileInput.close();

        // Encrypt files
        byte[] encryptedFileBytes = encryptFile(fileBytes, ecipher);

        //TODO: Send over file name (Change depending on IDE/cmdline)
//            out.println(args[0]); // command line argument
        out.println("largeFile.txt"); // IDE

        // send filesize in bytes
        out.println(encryptedFileBytes.length);

        // send byteString
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

    public static void Verify(X509Certificate signedCert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            signedCert.checkValidity();
//            signedCert.verify(key);
            System.out.println("Certificate verified!");
        } catch (Exception e) {
            System.out.println("Certificate verification failed!");
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
                //System.out.println(Arrays.toString(tempBuff));
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
