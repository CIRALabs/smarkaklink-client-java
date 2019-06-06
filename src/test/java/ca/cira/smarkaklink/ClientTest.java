package ca.cira.smarkaklink;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;

public class ClientTest {
    private Client client;

    @BeforeTest
    public void setup() throws EnvironmentException, CertificateException {
        client = new Client();
        client.initialize();
    }

    @Test
    public void testEnrollWithManufacturer() throws IOException, UnexpectedResponseException, CertificateException, EnvironmentException {
        client.enrollWithManufacturer(new URL("https://[::1]:9443/.well-known/est/smarkaklink"));
    }
}