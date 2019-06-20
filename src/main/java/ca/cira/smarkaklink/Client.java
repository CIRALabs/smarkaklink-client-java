package ca.cira.smarkaklink;

import ca.cira.smarkaklink.crypto.SmarkaklinkKeys;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Logger;

public class Client {

    public final static Logger logger = Logger.getLogger("SMARKAKLINK");
    private final static int READ_TIMEOUT = 1500;
    private final static int CONNECT_TIMEOUT = 1500;

    private SmarkaklinkKeys smarkaklinkKeys;

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
            case HttpURLConnection.HTTP_MOVED_TEMP:
                // TODO: Implement OAuth callback
                // No break for now
            default:
                throw new UnexpectedResponseException(responseCode);
        }

        return true;
    }
}
