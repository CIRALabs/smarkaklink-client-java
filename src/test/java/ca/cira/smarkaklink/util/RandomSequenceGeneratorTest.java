package ca.cira.smarkaklink.util;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.stream.IntStream;

import static ca.cira.smarkaklink.util.RandomSequenceGenerator.randomNumericalSequence;
import static ca.cira.smarkaklink.util.RandomSequenceGenerator.randomSequence;

public class RandomSequenceGeneratorTest {

    @DataProvider(name = "lengths")
    public static Object[][] lengths() {
        // very contrived way of having some fun with streams
        return IntStream.rangeClosed(0, 10).mapToObj(i -> new Object[] {(int)Math.pow(2, i), (int)Math.pow(2, i)}).toArray(Object[][]::new);
    }

    @Test(dataProvider = "lengths")
    public void testRandomNumericalSequence(int length, int expected) {
        String sequence = randomNumericalSequence(length);
        Assert.assertEquals(sequence.length(), expected);
        Assert.assertTrue(sequence.matches("\\d+"));
    }

    @Test(dataProvider = "lengths")
    public void testRandomSequence(int length, int expected) {
        String sequence = randomSequence(length);
        Assert.assertEquals(sequence.length(), expected);
        Assert.assertTrue(sequence.matches("\\w+"));
    }

}