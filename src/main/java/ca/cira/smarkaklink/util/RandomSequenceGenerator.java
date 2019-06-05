package ca.cira.smarkaklink.util;

import java.security.SecureRandom;
import java.util.stream.Collectors;

/**
 * Helper function to generate some random sequences.
 */
public class RandomSequenceGenerator {

    /**
     * Generate a random numerical sequence.
     * @param length Length of the (output) sequence to generate.
     */
    public static String randomNumericalSequence(int length) {
        return new SecureRandom().ints(0, 9)
                .mapToObj(i -> Integer.toString(i, 10))
                .distinct().limit(length).collect(Collectors.joining());
    }
}
