import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class Authentication {

    public static X509Certificate CAcert;
    public static PublicKey key;


    public Authentication() throws FileNotFoundException, CertificateException {
        // create X509Certificate object
        InputStream fis = new FileInputStream("C:\\Pinardy\\Term_5\\50.005 - Computer Systems Engineering\\ProgAssignment2\\1001520.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CAcert =(X509Certificate)cf.generateCertificate(fis);

        // extract public key from X509Certificate object
        key = CAcert.getPublicKey();
    }


    public static void verify(X509Certificate signedCert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        signedCert.checkValidity();
        signedCert.verify(key);
    }

    public static void main(String[] args) throws FileNotFoundException, CertificateException {
        Authentication au = new Authentication();

        try {
            au.verify(CAcert);
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


}
