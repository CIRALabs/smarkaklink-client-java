package ca.cira.smarkaklink;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ClientTest {
    private Client client;

    @BeforeTest
    public void setup() throws EnvironmentException, CertificateException, KeyStoreException {
        client = new Client();
        client.initialize();
    }

    @Test
    public void testEnrollWithManufacturer() throws IOException, UnexpectedResponseException, CertificateException, EnvironmentException {
        client.enrollWithManufacturer(new URL("https://[::1]:9443/.well-known/est/smarkaklink"));
    }

    @Test
    public void testFetchVoucherRequest() throws IOException, EnvironmentException, UnexpectedResponseException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        // This is the public key of Smarkaklink-n3ce618
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7Vr983Ya8xiFvLAA2wgNH0fgGwUA6FGsN5yzkDIYoXQRwLwa2RSkLRluJ8/RGQzUBAOQVe1HMrJijdteV0hJA=="));
        KeyFactory kf = KeyFactory.getInstance("ECDSA");
        PublicKey arKey = kf.generatePublic(spec);
//        Assert.assertTrue(client.fetchVoucherRequest(new URL("https://127.0.0.1:8443/.well-known/est/requestvoucherrequest"), arKey));
        client.fetchVoucherRequest(new URL("https://127.0.0.1:8443/.well-known/est/requestvoucherrequest"), arKey);
    }
}