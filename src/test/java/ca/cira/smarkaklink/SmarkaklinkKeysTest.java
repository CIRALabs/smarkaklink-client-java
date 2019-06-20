package ca.cira.smarkaklink;

import ca.cira.smarkaklink.crypto.SmarkaklinkKeys;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class SmarkaklinkKeysTest {

    private SmarkaklinkKeys keys;

    @BeforeTest
    public void setup() throws EnvironmentException {
        keys = new SmarkaklinkKeys();
    }

    @Test
    public void testGenerateIDevIdFromEther() throws EnvironmentException, CertificateException, KeyStoreException {
        keys.generateSelfDevId();
        KeyPair keyPair = keys.getSelfDevIdKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        Assert.assertEquals(publicKey.getAlgorithm(), "EC");
        Assert.assertEquals(publicKey.getFormat(), "X.509");

        Certificate cert = keys.getSelfDevIdCertificate();
        Assert.assertEquals(cert.getPublicKey(), publicKey);
        Assert.assertTrue(cert instanceof X509Certificate);
        X509Certificate x509Cert = (X509Certificate)cert;

        Assert.assertEquals(x509Cert.getSigAlgName(), "SHA256WITHECDSA");
        Assert.assertEquals(x509Cert.getSubjectDN(), x509Cert.getIssuerDN());

        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cal.add(Calendar.MINUTE, -1);
        Date nowDelta = cal.getTime();
        cal.setTime(now);
        cal.add(Calendar.YEAR, 2);
        Date now2Y = cal.getTime();

        Date beforeDate = x509Cert.getNotBefore();
        Assert.assertTrue(beforeDate.before(now) && beforeDate.after(nowDelta));

        Date afterDate = x509Cert.getNotAfter();
        Assert.assertTrue(afterDate.after(now) && afterDate.before(now2Y));
    }
}