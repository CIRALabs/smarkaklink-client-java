package ca.cira.smarkaklink;

import ca.cira.smarkaklink.crypto.SmarkaklinkKeys;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Logger;

public class Client {

    public final static Logger logger = Logger.getLogger("SMARKAKLINK");
    private final static int READ_TIMEOUT = 1500;
    private final static int CONNECT_TIMEOUT = 1500;

    private SmarkaklinkKeys smarkaklinkKeys;

    public Client() {
        smarkaklinkKeys = new SmarkaklinkKeys();
    }

    public void initialize() throws EnvironmentException, CertificateException {
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

    public boolean enrollWithManufacturer(URL manufacturerURL) throws UnexpectedResponseException, IOException, EnvironmentException, CertificateException {
        HttpURLConnection httpConnection = null;

        /* This should not be done with proper MASA certificate */
        try {
            // Disable certificate validation
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, getNoSecurityTrustManagers(), new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            // Create all-trusting host name verifier
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new EnvironmentException("Cannot set SSL context", e);
        }

        try {
            httpConnection = (HttpURLConnection) manufacturerURL.openConnection();
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
