package ProgAssignment2.src;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class Authentication {
    public static void main(String[] args) throws FileNotFoundException, CertificateException {
        Authentication au = new Authentication();
        
        // create X509Certificate object for CA.crt
        X509Certificate CAcert = au.CreateX509Cert("CA.crt");
        
        // create X509Certificate object for 1001520.crt
        X509Certificate MyCert = au.CreateX509Cert("1001520.crt");
        
        // extract public key from CAcert
        PublicKey key = CAcert.getPublicKey();
        
        try {
            au.Verify(MyCert,key);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
    
    public X509Certificate CreateX509Cert(String cert) throws CertificateException, FileNotFoundException{
    	InputStream fis = new FileInputStream(cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate X509cert =(X509Certificate)cf.generateCertificate(fis);
        return X509cert;
    }

    public void Verify(X509Certificate signedCert, PublicKey key) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
        	signedCert.checkValidity();
            signedCert.verify(key);
            System.out.println("Certificate verified!");
        } catch (Exception e){
        	System.out.println("Certificate verification failed!");
        }
    }


}
