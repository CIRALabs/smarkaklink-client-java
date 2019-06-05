package ca.cira.smarkaklink;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class ClientTest {
    private Client client;

    @BeforeTest
    public void setup() {
        client = new Client();
    }

    @Test
    public void testDoSomething() {
        client.doSomething();
    }
}