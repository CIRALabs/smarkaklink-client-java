package ca.cira.smarkaklink;

/**
 * Exception thrown when a remote party (eg. AR) respond to a request in an unexpected way.
 */
public class UnexpectedResponseException extends Exception {
    public UnexpectedResponseException(String from, int responseCode) {
        super("Got unexpected response code from " + from + ": " + responseCode);
    }

    public UnexpectedResponseException(String from, String message) {
        super("Got invalid response from " + from + ": " + message);
    }
}
