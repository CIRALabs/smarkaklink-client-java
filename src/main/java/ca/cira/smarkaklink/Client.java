package ca.cira.smarkaklink;

import ca.cira.smarkaklink.crypto.SmarkaklinkKeys;
import ca.cira.smarkaklink.util.RandomSequenceGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.logging.Logger;

public class Client {

    public final static Logger logger = Logger.getLogger("SMARKAKLINK");

    private final static int READ_TIMEOUT = 1500;
    private final static int CONNECT_TIMEOUT = 1500;
    private final static String MASA_URL_EXTENSION_OID = "1.3.6.1.4.1.46930.2";

    private SmarkaklinkKeys smarkaklinkKeys;
    private String spnonce;
    private String masaURL;

    public Client() throws EnvironmentException {
        smarkaklinkKeys = new SmarkaklinkKeys();
    }

    public void initialize() throws EnvironmentException, CertificateException, KeyStoreException {
        smarkaklinkKeys.generateSelfDevId();
    }

    private TrustManager[] getNoSecurityTrustManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(
                            X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            X509Certificate[] certs, String authType) {
                    }
                }
        };
    }

    private void setSSLContext(HttpsURLConnection connection) throws EnvironmentException {
        /* This should not be done with proper MASA certificate */
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(smarkaklinkKeys.getKeyStore(), "".toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();

            // Disable certificate validation
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, getNoSecurityTrustManagers(), new SecureRandom());
            connection.setSSLSocketFactory(sc.getSocketFactory());
            // Create all-trusting host name verifier
            connection.setHostnameVerifier((hostname, session) -> true);
        } catch (NoSuchAlgorithmException | KeyManagementException | UnrecoverableKeyException | KeyStoreException e) {
            throw new EnvironmentException("Cannot set SSL context", e);
        }

    }


    /**
     * Execute the first step of the Smarkaklink specification: Enroll with the manufacturer.
     * <p>
     * In this step, the client will connect to the manufacturer and send its public key.
     * The manufacturer will generate and sign a certificate based in this public key.
     *
     * @param manufacturerURL URL of the manufacturer, most likely retrieved from the QR code on the device.
     * @return True if certificate has been retrieved, False otherwise.
     * @throws UnexpectedResponseException when the server returns an unexpected response.
     * @throws IOException                 when an error occurred when connecting to the manufacturer.
     * @throws EnvironmentException        if there is an issue with the environment (mostly security/provider related).
     * @throws CertificateException        if the SelfDevId certificate cannot be read.
     */
    public boolean enrollWithManufacturer(URL manufacturerURL) throws UnexpectedResponseException, IOException, EnvironmentException, CertificateException {
        HttpsURLConnection httpConnection = null;

        try {
            httpConnection = (HttpsURLConnection) manufacturerURL.openConnection();
            setSSLContext(httpConnection);

            httpConnection.setRequestMethod("POST");
            httpConnection.setRequestProperty("Content-Type", "application/json");
            httpConnection.setRequestProperty("Accept", "application/pkcs7");
            httpConnection.setDoOutput(true);
            httpConnection.setDoInput(true);
            httpConnection.setConnectTimeout(CONNECT_TIMEOUT);
            httpConnection.setReadTimeout(READ_TIMEOUT);

            JSONObject jsonParam = new JSONObject();
            jsonParam.put("cert", Base64.getUrlEncoder().encodeToString(smarkaklinkKeys.getSelfDevIdCertificate().getEncoded()));

            DataOutputStream os = new DataOutputStream(httpConnection.getOutputStream());
            os.writeBytes(jsonParam.toString());
            os.flush();
            os.close();
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }

        int responseCode = httpConnection.getResponseCode();
        String response = httpConnection.getResponseMessage();
        switch (responseCode) {
            case HttpURLConnection.HTTP_NOT_FOUND:
            case HttpURLConnection.HTTP_BAD_REQUEST:
                logger.warning("Manufacturer refuses smarkaklink enroll: " + response);
                return false;
            case HttpURLConnection.HTTP_OK:
                smarkaklinkKeys.setLDevIdCertificate(new DataInputStream(httpConnection.getInputStream()));
                break;
            case HttpURLConnection.HTTP_NO_CONTENT:
                // TODO: Retrieve cert at Location
                // No break for now
            case HttpURLConnection.HTTP_MOVED_TEMP:
                // TODO: Implement OAuth callback
                // No break for now
            default:
                throw new UnexpectedResponseException("manufacturer", responseCode);
        }

        return true;
    }

    /**
     * Execute the next step of the Smarkaklink specification:
     * Pledge Requests Voucher-Request from the Adolescent Registrar.
     * <p>
     * In this step, the client will connect to the AR using its SelfDevId as a client certificate, and send it a
     * random SPnonce, encrypted to the AR's public key (found in QR code).
     * The AR will return a VoucherRequest object.
     *
     * @param arAddress URL of the AR.
     * @param arKey     The public key found in the QR code.
     * @throws InvalidKeyException when the arKey is not valid in the context (invalid algorithm or size).
     */
    public boolean fetchVoucherRequest(URL arAddress, PublicKey arKey) throws IOException, EnvironmentException, InvalidKeyException, CertificateException, UnexpectedResponseException {
        HttpsURLConnection httpConnection = null;
        spnonce = RandomSequenceGenerator.randomSequence(16);

        byte[] encryptedSPnonce;

        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.ENCRYPT_MODE, arKey);
            encryptedSPnonce = cipher.doFinal(spnonce.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EnvironmentException("Cannot instantiate cipher instance", e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new EnvironmentException("Cannot encrypt SPnonce", e);
        }

        try {
            httpConnection = (HttpsURLConnection) arAddress.openConnection();
            setSSLContext(httpConnection);

            httpConnection.setRequestMethod("POST");
            httpConnection.setRequestProperty("Content-Type", "application/json");
            httpConnection.setRequestProperty("Accept", "application/voucher-cms+json");
            httpConnection.setDoOutput(true);
            httpConnection.setDoInput(true);
            httpConnection.setConnectTimeout(CONNECT_TIMEOUT);
            httpConnection.setReadTimeout(READ_TIMEOUT);

            JSONObject jsonParam = new JSONObject();
            JSONObject vr = new JSONObject();
            // FIXME: This does not validate in mud-supervisor...
            // vr.put("voucher-challenge-nonce", spnonce);
            // FIXME: For now, use an hardcoded SPnonce to the public key of Smarkaklink-n3ce618
            vr.put("voucher-challenge-nonce", "AgQRXBZKtsAxJZmzrM_PUSq3W6lYZnSQ9Ufyv9RJuRIjRte_ojEQi6Ayxir8kPkInJ_nAcLATbtSUCviMSd9iyUA2-CZt3U_AlJDoD4jed3vuXRv2g==");

            jsonParam.put("ietf:request-voucher-request", vr);

            DataOutputStream os = new DataOutputStream(httpConnection.getOutputStream());
            os.writeBytes(jsonParam.toString());
            os.flush();
            os.close();
            // Use the TLS cert to retrieve the MASA URL
            retrieveMASAURL(httpConnection);
        } finally {
            if (httpConnection != null) {
                httpConnection.disconnect();
            }
        }

        int responseCode = httpConnection.getResponseCode();
        switch (responseCode) {
            case HttpURLConnection.HTTP_NOT_FOUND:
            case HttpURLConnection.HTTP_BAD_REQUEST:
                logger.warning("AR refuses smarkaklink voucher request request: " + httpConnection.getResponseMessage());
                return false;
            case HttpURLConnection.HTTP_OK:
                try {
                    return processRequestVoucherRequestResponse(httpConnection.getInputStream());
                } catch (CMSException | OperatorCreationException e) {
                    throw new UnexpectedResponseException("AR", e.getMessage());
                }
            default:
                throw new UnexpectedResponseException("AR", responseCode);
        }

    }

    /**
     * Process a request-voucher-request response from the AR.
     */
    private boolean processRequestVoucherRequestResponse(InputStream response) throws CMSException, CertificateException, OperatorCreationException, IOException {
        CMSSignedData s = new CMSSignedData(response);
        SignerInformationStore signers = s.getSignerInfos();
        Store<X509CertificateHolder> certs = s.getCertificates();
        boolean verified = false;

        for (SignerInformation signer : signers.getSigners()) {
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
            if (!certCollection.isEmpty()) {
                X509CertificateHolder cert = certCollection.iterator().next();
                JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
                SignerInformationVerifier siv = verifier.build(cert);
                if (signer.verify(siv)) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) {
            logger.warning("Cannot verify signature on returned voucher request object");
            return false;
        }
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) s.getSignedContent();
        String content = new String(signedContent.getInputStream().readAllBytes());
        JSONObject vr = new JSONObject(content);
        return vr.getJSONObject("ietf-voucher-request:voucher").getString("nonce").equals(spnonce);
    }

    /**
     * Given an open {@link HttpsURLConnection}, retrieve the MASA URL in the server's certificate extension
     */
    private void retrieveMASAURL(HttpsURLConnection connection) throws SSLPeerUnverifiedException {
        Certificate[] certs = connection.getServerCertificates();
        if (certs.length < 1) {
            // Well, we really have a problem here!
            throw new RuntimeException("AR has certificate chain with 0 certificates");
        }
        X509Certificate arCertificate = (X509Certificate)certs[0];
        // FIXME: We should not have to substring here
        masaURL = new String(arCertificate.getExtensionValue(MASA_URL_EXTENSION_OID)).substring(4);
        logger.info("MASA located at " + masaURL);
    }
}
