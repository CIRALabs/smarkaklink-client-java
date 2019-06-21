package ca.cira.smarkaklink.crypto;

import ca.cira.smarkaklink.EnvironmentException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Abstraction of certificate generation.
 */
public class CertificateGenerator {

    private static final String SIGNATURE = "SHA256withECDSA";

    private static final Provider bcProvider = new BouncyCastleProvider();

    public static void initialize() {
        Security.addProvider(bcProvider);
    }

    /**
     * Generate a self-signed certificate.
     *
     * @param keyPair KeyPair to use to generate the certificate.
     * @param subjectDN Subject used in the certificate.
     * @param serialNumber Serial number to use.
     * @return Self-signed certificate.
     * @throws CertificateException if the conversion is unable to be made.
     * @throws EnvironmentException if there is an issue with the environment (mostly security/provider related).
     */
    public static X509Certificate selfSign(KeyPair keyPair, String subjectDN, BigInteger serialNumber) throws CertificateException, EnvironmentException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 2);

        Date endDate = calendar.getTime();

        ContentSigner contentSigner;
        try {
            contentSigner = new JcaContentSignerBuilder(SIGNATURE).build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new EnvironmentException("Cannot create content signer", e);
        }

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(dnName, serialNumber, startDate, endDate, dnName, publicKeyInfo);

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }
}
