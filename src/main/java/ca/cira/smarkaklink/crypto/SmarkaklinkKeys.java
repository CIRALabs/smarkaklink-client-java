package ca.cira.smarkaklink.crypto;

import ca.cira.smarkaklink.EnvironmentException;
import ca.cira.smarkaklink.util.RandomSequenceGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * Encapsulate keys used in the Smarkaklink protocol.
 */
public class SmarkaklinkKeys {

    private static final String KEY_ALGORITHM = "EC";
    private static final String CURVE = "prime256v1";
    private final KeyStore keyStore;
    private KeyPair selfDevId;
    private X509Certificate selfDevIdCertificate;
    private X509Certificate lDevIdCertificate;


    public SmarkaklinkKeys() throws EnvironmentException {
        CertificateGenerator.initialize();
        // TODO: For now, create new KeyStore each time. Will need to save/read it from storage
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, "".toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new EnvironmentException("Cannot instantiate a key store", e);
        }
    }

    /**
     * Generate a KeyPair to be used in SelfDevId.
     *
     * @throws EnvironmentException if there is an issue with the environment (mostly security/provider related).
     */
    private void generateSelfDevIdKeyPair() throws EnvironmentException {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance(KEY_ALGORITHM, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EnvironmentException("Cannot instantiate keypair generator for " + KEY_ALGORITHM, e);
        }
        AlgorithmParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
        try {
            generator.initialize(ecSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EnvironmentException("Cannot initialize keypair generator for curve " + CURVE, e);
        }

        selfDevId = generator.generateKeyPair();
    }

    /**
     * Generate the KeyPair and self-signed certificate to be used for SelfDevId.
     *
     * @throws EnvironmentException if there is an issue with the environment (mostly security/provider related).
     * @throws CertificateException if the certificate could not be generated.
     * @throws KeyStoreException if an error occurs when storing the SelfDevId into the keystore.
     */
    public void generateSelfDevId() throws EnvironmentException, CertificateException, KeyStoreException {
        // No key-pair defined, generate them
        generateSelfDevIdKeyPair();

        // We have our set of public/private keys, now generate the certificate
        generateSelfDevId(selfDevId);
    }

    /**
     * Generate the self-signed SelfDevId certificate using an existing KeyPair.
     *
     * @param keyPair KeyPair to use in generated certificate.
     * @throws EnvironmentException if there is an issue with the environment (mostly security/provider related).
     * @throws CertificateException if the certificate could not be generated.
     * @throws KeyStoreException if an error occurs when storing the SelfDevId into the keystore.
     */
    public void generateSelfDevId(KeyPair keyPair) throws CertificateException, EnvironmentException, KeyStoreException {
        selfDevId = keyPair;
        String serial = RandomSequenceGenerator.randomNumericalSequence(5);
        BigInteger serialNumber = new BigInteger(serial);
        selfDevIdCertificate = CertificateGenerator.selfSign(keyPair,
                                                             "C=Canada,OU=Smarkaklink-" + serial,
                                                             serialNumber);

        Certificate[] chain = new Certificate[]{selfDevIdCertificate};
        keyStore.setKeyEntry("SelfDevId", selfDevId.getPrivate(), "".toCharArray(), chain);
    }

    public KeyPair getSelfDevIdKeyPair() {
        return selfDevId;
    }

    public Certificate getSelfDevIdCertificate() {
        return selfDevIdCertificate;
    }

    public void setLDevIdCertificate(InputStream input) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        lDevIdCertificate = (X509Certificate) factory.generateCertificate(input);
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
