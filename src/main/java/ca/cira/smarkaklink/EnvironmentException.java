package ca.cira.smarkaklink;

/**
 * Exception thrown when the library cannot be configured/executed in this environment.
 */
public class EnvironmentException extends Exception {
    public EnvironmentException(String message, Throwable cause) {
        super(message + ": " + cause.getMessage(), cause);
    }
}
