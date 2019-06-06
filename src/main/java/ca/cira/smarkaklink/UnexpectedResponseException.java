package ca.cira.smarkaklink;

public class UnexpectedResponseException extends Exception {
    private int responseCode;

    public UnexpectedResponseException(int responseCode) {
        super("Got unexpected response code: " + responseCode);
    }
}
