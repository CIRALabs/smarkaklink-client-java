package ca.cira.smarkaklink.util;

import java.security.SecureRandom;
import java.util.stream.Collectors;

/**
 * Helper function to generate some random sequences.
 */
public class RandomSequenceGenerator {

    /**
     * Generate a random numerical sequence.
     *
     * @param length Length of the (output) sequence to generate.
     */
    public static String randomNumericalSequence(int length) {
        return randomBaseSequence(length, 10);
    }

    /**
     * Generate a random alpha-numerical sequence.
     *
     * @param length Length of the (output) sequence to generate.
     */
    public static String randomSequence(int length) {
        return randomBaseSequence(length, 36);
    }

    private static String randomBaseSequence(int length, int base) {
        return new SecureRandom().ints(0, base - 1)
                .mapToObj(i -> Integer.toString(i, base))
                .limit(length).collect(Collectors.joining());
    }
}
