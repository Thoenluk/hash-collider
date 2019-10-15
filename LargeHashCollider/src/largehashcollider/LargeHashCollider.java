/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package largehashcollider;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 * @author Lukas
 */
public class LargeHashCollider {

    /**
     * Find a BigInteger which, when hashed with the algorithm described in
     * (hashAlg), will contain the byte values in (required) somewhere within
     * its hash.
     *
     * @param required The byte sequence that is to appear in the hash.
     * @param hashAlg The hash algorithm to be used. Must be a valid value for
     * MessageDigest.getInstance.
     * @param printAsChars Whether to print the hashes as bytewise chars or
     * 0-255 numerical values. Hashes are usually printed in char form (true).
     * @param print Whether to print the generation results at all.
     * @return The BigInteger which will produce the desired hash.
     *
     */
    public static BigInteger findCollision(byte[] required, String hashAlg, boolean printAsChars, boolean print) {
        long startTime = System.currentTimeMillis();
        BigInteger token = BigInteger.ONE;
        MessageDigest md;
        SecureRandom random = new SecureRandom();
        boolean collisionFound = false;
        byte[] hashedToken;
        int i, j, numbersTried = 0;
        try {
            md = MessageDigest.getInstance(hashAlg);
            do {
                numbersTried++;
                token = new BigInteger(512, random);
                hashedToken = md.digest(token.toByteArray());
                i = 0;
                while (!collisionFound && required.length + i < hashedToken.length) {
                    j = 0;
                    while (required[j] == hashedToken[i + j]) {
                        j++;
                        if (j == required.length) {
                            collisionFound = true;
                            break;
                        }
                    }
                    i++;
                }
            } while (!collisionFound);
            if (print) {
                printGenerationResults(required, hashedToken, numbersTried, startTime, printAsChars);
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return token;
    }

    /**
     * Find a BigInteger which, when hashed with the algorithm described in
     * (hashAlg), will contain the byte values in (required), starting at an
     * offset of exactly (location) bytes from the start.
     *
     * @param required The byte sequence that is to appear in the hash.
     * @param location The byte offset from the start of the hash. Must be less
     * than the length of the produced hash minus the length of the required
     * sequence, to ensure the required sequence fits into the hash.
     * @param hashAlg The hash algorithm to be used. Must be a valid value for
     * MessageDigest.getInstance.
     * @param printAsChars Whether to print the hashes as bytewise chars or
     * 0-255 numerical values. Hashes are usually printed in char form (true).
     * @param print Whether to print the generation results at all.
     * @return The BigInteger which will produce the desired hash.
     */
    public static BigInteger findCollisionAtSpecificLocation(byte[] required, int location, String hashAlg, boolean printAsChars, boolean print) {
        long startTime = System.currentTimeMillis();
        BigInteger token = BigInteger.ONE;
        MessageDigest md;
        SecureRandom random = new SecureRandom();
        boolean collisionFound;
        byte[] hashedToken;
        int i, j, numbersTried = 0;
        try {
            // Select the message digest for the hash computation -> SHA-256
            md = MessageDigest.getInstance(hashAlg);
            do {
                collisionFound = true;
                numbersTried++;
                token = new BigInteger(512, random);
                hashedToken = md.digest(token.toByteArray());
                for (i = 0; i < required.length; i++) {
                    collisionFound = required[i] == hashedToken[i + location] ? collisionFound : false;
                }
            } while (!collisionFound);
            if (print) {
                printGenerationResults(required, hashedToken, numbersTried, startTime, printAsChars);
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return token;
    }

    /**
     * Print the required sequence, the target hash containing it, the amount of
     * numbers tried, and the time elapsed to the console.
     *
     * @param required The required byte sequence.
     * @param hashedToken The hash containing the desired sequence.
     * @param numbersTried Amount of numbers tried until a collision was found.
     * @param startTime System time in milliseconds at the start of the search.
     * @param printAsChars Whether to print the hashes as bytewise chars or
     * 0-255 numerical values. Hashes are usually printed in char form (true).
     */
    private static void printGenerationResults(byte[] required, byte[] hashedToken, int numbersTried, long startTime, boolean printAsChars) {
        long endTime = System.currentTimeMillis();
        StringBuilder sb = new StringBuilder();
        StringBuilder rq = new StringBuilder();
        if (printAsChars) {
            for (byte b : hashedToken) {
                sb.append((char) b);
            }
            for (byte b : required) {
                rq.append((char) b);
            }
        } else {
            for (byte b : hashedToken) {
                sb.append(b);
                sb.append(' ');
            }
            for (byte b : required) {
                rq.append(b);
                rq.append(' ');
            }
        }
        System.out.println("Collision found for target " + rq);
        System.out.println(sb);
        System.out.println("And it only took " + numbersTried + " numbers and " + (endTime - startTime) + " milliseconds! *cough*");
    }

}
