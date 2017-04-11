package ProgAssignment2.src;


import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
 
public class SecStoreClient {
	private static final int PORT = 4321;
	private static final String HOSTNAME = "localhost";
	private static final String auMessage = "Hello, this is SecStore!";
	private static final String serverCertStr = "serverCert.crt";
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
        
        try{
        	X509Certificate serverCert = CreateX509Cert(serverCertStr);
            // Extract public key from serverCert
            key = serverCert.getPublicKey();
            // Verify that certificate is legitimate
            Verify(serverCert,key);
        } catch (Exception e){
        	e.printStackTrace();
        }
        
        // Decrypting the signed certificate
        System.out.println("Decrypting the signed certificate...");
        Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        byte[] signedMessageBytes = DatatypeConverter.parseBase64Binary(signedMessage);
        byte[] decryptedCertBytes = dcipher.doFinal(signedMessageBytes);
        String decryptedMessage = new String(decryptedCertBytes, "UTF-16");
        boolean checkResult = decryptedMessage.equals(signedMessage);
        
        // If check fail
        if (!checkResult){
        	out.println("Bye!");
        	out.close();
        	in.close();
        	echoSocket.close();
//        	br.close();
        }
        
        // If check succeeded
        else {
        	
        }
    }
    
    public static X509Certificate CreateX509Cert(String cert) throws CertificateException, FileNotFoundException{
    	InputStream fis = new FileInputStream(cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate X509cert =(X509Certificate)cf.generateCertificate(fis);
        return X509cert;
    }

    public static void Verify(X509Certificate signedCert, PublicKey key) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
        	signedCert.checkValidity();
            signedCert.verify(key);
            System.out.println("Certificate verified!");
        } catch (Exception e){
        	System.out.println("Certificate verification failed!");
        }
    }
}
