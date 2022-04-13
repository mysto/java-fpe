package com.privacylogistics;

/*
 * Format-Preserving Encryption for FF3
 *
 * Copyright (c) 2021 Schoening Consulting LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

import java.nio.charset.StandardCharsets;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class FF3Cipher implements the FF3 format-preserving encryption algorithm
 */
public class FF3Cipher {
    /**
     * Constructor with default radix of 10.
     *
     * @param key   encryption key used to initialize AES ECB
     * @param tweak used in each round and split into right and left sides
     */
    public FF3Cipher(String key, String tweak) {
        this(key, tweak, 10);
    }

    /**
     * Constructor with a custom alphabet
     *
     * @param key   encryption key used to initialize AES ECB
     * @param tweak used in each round and split into right and left sides
     * @param alphabet the cipher alphabet
     */
    public FF3Cipher(String key, String tweak, String alphabet) {
        this.alphabet = alphabet;
        this.radix = alphabet.length();

        byte[] keyBytes = hexStringToByteArray(key);

        // Calculate range of supported message lengths [minLen..maxLen]
        // radix 10: 6 ... 56, 26: 5 ... 40, 36: 4 .. 36

        // Per revised spec, radix^minLength >= 1,000,000
        this.minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));

        // We simplify the specs log[radix](2^96) to 96/log2(radix) using the log base change rule
        this.maxLen = (int) (2 * Math.floor(Math.log(Math.pow(2, 96)) / Math.log(radix)));
        // ToDo: With log2 we could further simplify this
        // this.maxLen = (int) (2 * Math.floor(96/Math.log2(radix)));

        int keyLen = keyBytes.length;
        // Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
        if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
            throw new IllegalArgumentException("key length " + keyLen + " but must be 128, 192, or 256 bits");
        }

        // While FF3 allows radices in [2, 2^16], currently only tested up to 64
        if ((radix < 2) || (radix > MAX_RADIX)) {
            throw new IllegalArgumentException("radix must be between 2 and 256, inclusive");
        }

        // Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
        if ((this.minLen < 2) || (this.maxLen < this.minLen)) {
            throw new IllegalArgumentException("minLen or maxLen invalid, adjust your radix");
        }

        this.tweakBytes = hexStringToByteArray(tweak);

        // AES block cipher in ECB mode with the block size derived based on the length of the key
        // Always use the reversed key since Encrypt and Decrypt call cipher expecting that
        // Feistel ciphers use the same func for encrypt/decrypt, so mode is always ENCRYPT_MODE

        try {
            reverseBytes(keyBytes);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            // this could happen if the JRE doesn't have the ciphers
            throw new RuntimeException(e);
        }
    }

    /**
     * Constructor with a standardized radix
     *
     * @param key   encryption key used to initialize AES ECB
     * @param tweak used in each round and split into right and left sides
     * @param radix the domain of the alphabet, 10, 26 or 36
     */
    public FF3Cipher(String key, String tweak, int radix) {
        this(key, tweak, alphabetForBase(radix));
    }

    /**
     * Encrypt a value  - convenience method to override tweak
     * @param plaintext   a plaintext to encrypt
     * @param tweak       a local tweak for encrypting
     * @return            the ciphertext
     * @throws BadPaddingException internal error
     * @throws IllegalBlockSizeException internal error
     */
    @SuppressWarnings("unused")
    public String encrypt(String plaintext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = hexStringToByteArray(tweak);
        return encrypt(plaintext);
    }

    /**
     * Encrypt a value
     * @param plaintext   a plaintext to encrypt
     * @return            the ciphertext
     * @throws BadPaddingException internal error
     * @throws IllegalBlockSizeException internal error
     */
    public String encrypt(String plaintext) throws BadPaddingException, IllegalBlockSizeException {
        int n = plaintext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = plaintext.substring(0, u);
        String B = plaintext.substring(u);
        logger.trace("r {} A {} B {}", this.radix, A, B);

        if ((this.tweakBytes.length != TWEAK_LEN) && (this.tweakBytes.length != TWEAK_LEN_NEW)) {
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 56 or 64 bits",
                    this.tweakBytes.length));
        }

        // Calculate the tweak
        logger.trace("tweak: {}", byteArrayToHexString(this.tweakBytes));

        byte[] tweak64 = (this.tweakBytes.length == TWEAK_LEN_NEW) ?
                calculateTweak64_FF3_1(this.tweakBytes) : this.tweakBytes;

        byte[] Tl = Arrays.copyOf(tweak64, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(tweak64, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether it is even or odd

        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        logger.trace("u {} v {} modU: {} modV: {}", u, v, modU, modV);
        logger.trace("tL: {} tR: {}", byteArrayToHexString(Tl), byteArrayToHexString(Tr));

        for (byte i = 0; i < NUM_ROUNDS; ++i) {
            int m;
            BigInteger c;
            byte[] W;

            // Determine alternating Feistel round side, right or left
            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = calculateP(i, this.alphabet, W, B);
            reverseBytes(P);

            // Calculate S by operating on P in place
            byte[] S = this.aesCipher.doFinal(P);
            reverseBytes(S);
            logger.trace("\tS: {}", byteArrayToHexString(S));

            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);

            // Calculate c
            c = decode_int(reverseString(A), alphabet);

            c = c.add(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            logger.trace("\tm: {} A: {} c: {} y: {}", m, A, c, y);

            String C = encode_int_r(c, this.alphabet, m);

            // Final steps
            A = B;
            B = C;
            logger.trace("A: {} B: {}", A, B);
        }
        return A + B;
    }

    /**
     * Decrypt a value - convenience method to override tweak
     * @param ciphertext   a ciphertext to decrypt
     * @param tweak        a local tweak for decrypting
     * @return             the plaintext
     * @throws BadPaddingException internal error
     * @throws IllegalBlockSizeException internal error
     */
    @SuppressWarnings("unused")
    public String decrypt(String ciphertext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = hexStringToByteArray(tweak);
        return decrypt(ciphertext);
    }

    /**
     * Decrypt a value
     * @param ciphertext   a ciphertext to decrypt
     * @return             the plaintext
     * @throws BadPaddingException internal error
     * @throws IllegalBlockSizeException internal error
     */
    public String decrypt(String ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        int n = ciphertext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = ciphertext.substring(0, u);
        String B = ciphertext.substring(u);

        if ((this.tweakBytes.length != TWEAK_LEN) && (this.tweakBytes.length != TWEAK_LEN_NEW)) {
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 56 or 64 bits",
                    this.tweakBytes.length));
        }

        // Calculate the tweak
        logger.trace("tweak: {}", byteArrayToHexString(this.tweakBytes));

        byte[] tweak64 = (this.tweakBytes.length == TWEAK_LEN_NEW) ?
                calculateTweak64_FF3_1(this.tweakBytes) : this.tweakBytes;

        byte[] Tl = Arrays.copyOf(tweak64, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(tweak64, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether it is even or odd

        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        logger.trace("modU: {} modV: {}", modU, modV);
        logger.trace("tL: {} tR: {}", byteArrayToHexString(Tl), byteArrayToHexString(Tr));

        for (byte i = (byte) (NUM_ROUNDS - 1); i >= 0; --i) {
            int m;
            BigInteger c;
            byte[] W;

            // Determine alternating Feistel round side, right or left
            if (i % 2 == 0) {
                m = u;
                W = Tr;
            } else {
                m = v;
                W = Tl;
            }

            // P is fixed-length 16 bytes
            P = calculateP(i, this.alphabet, W, A);
            reverseBytes(P);

            // Calculate S by operating on P in place
            byte[] S = this.aesCipher.doFinal(P);
            reverseBytes(S);
            logger.trace("\tS: {}", byteArrayToHexString(S));

            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);

            // Calculate c
            c = decode_int(reverseString(B), alphabet);

            c = c.subtract(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            logger.trace("\tm: {} B: {} c: {} y: {}", m, B, c, y);

            String C = encode_int_r(c, this.alphabet, m);

            // Final steps
            B = A;
            A = C;
            logger.trace("A: {} B: {}", A, B);
        }
        return A + B;
    }

    /**
     * For FF3-1, calculate a 64-bit tweak by transforming a 56-bit tweak
     * @param tweak56      an input 56-bit tweak
     * @return             the reconstituted tweak
     */
    protected static byte[] calculateTweak64_FF3_1(byte[] tweak56)
    {
        byte[] tweak64 = new byte[8];
        tweak64[0] = tweak56[0];
        tweak64[1] = tweak56[1];
        tweak64[2] = tweak56[2];
        tweak64[3] = (byte)(tweak56[3] & 0xF0);
        tweak64[4] = tweak56[4];
        tweak64[5] = tweak56[5];
        tweak64[6] = tweak56[6];
        tweak64[7] = (byte)((tweak56[3] & 0x0F) << 4);

        return tweak64;
    }

    /**
     * Calculate P, an intermediate value
     * @param i            an int
     * @param alphabet     an alphabet
     * @param W            a byte array
     * @param B            a string value
     * @return             a byte array
     */
    protected static byte[] calculateP(int i, String alphabet, byte[] W, String B) {

        byte[] P = new byte[BLOCK_SIZE];     // P is always 16 bytes, zero initialized

        // Calculate P by XORing W, i into the first 4 bytes of P
        // it only requires 1 byte, rest are 0 padding bytes
        // Anything XOR 0 is itself, so only need to XOR the last byte

        P[0] = W[0];
        P[1] = W[1];
        P[2] = W[2];
        P[3] = (byte) (W[3] ^ i);

        // The remaining 12 bytes of P are copied from reverse(B) with padding

        B = reverseString(B);
        byte[] bBytes = decode_int(B, alphabet).toByteArray();

        System.arraycopy(bBytes, 0, P, (BLOCK_SIZE - bBytes.length), bBytes.length);
        logger.trace("round: {} W: {} P: {}", i, byteArrayToHexString(W), byteArrayToIntString(P));
        return P;
    }

    /**
     * Reverse an immutable string
     * @param s            the original string
     * @return             the new string
     */
    protected static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    /**
     * Reverse a byte array in-place
     * @param b            a mutable byte array
     */
    protected void reverseBytes(byte[] b) {
        for (int i = 0; i < b.length / 2; i++) {
            byte temp = b[i];
            b[i] = b[b.length - i - 1];
            b[b.length - i - 1] = temp;
        }
    }

    /**
     * Returns a byte array containing hexadecimal values parsed from the string
     * @param s          a character string containing hexadecimal digits
     * @return           a byte array with the values parsed from the string
     */
    protected static byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * used for debugging
     * Java 17 has java.util.HexFormat
     * @param byteArray  a byte array
     * @return           a hex string encoding of a number
     */
    protected static String byteArrayToHexString(byte[] byteArray) {
        byte[] hexChars = new byte[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = (byte) HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = (byte) HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * used for debugging output
     * @param byteArray  a byte array
     * @return           a decimal string encoding of a number
     */
    protected static String byteArrayToIntString(byte[] byteArray) {
        return Arrays.toString(byteArray);
    }

    /**
     * Return a string representation of a number in the given base system
     * - the string is right padded with zeros to length
     * - the string is returned in reversed order expected by the calling cryptographic function
     * i.e., the decimal value 123 in five decimal places would be '32100'
     *
     *      examples:
     *         encode_int_r(10, 16,2)
     *          'A0'
     * @param n          the integer number
     * @param alphabet   the alphabet used for encoding
     * @param length     the length used for padding the output string
     * @return           a string encoding of the number
     */
    protected static String encode_int_r(BigInteger n, String alphabet, int length) {

        char[] x = new char[length];
        int i=0;

        BigInteger bbase =  BigInteger.valueOf(alphabet.length());
        while (n.compareTo(bbase) >= 0) {
            BigInteger b = n.mod(bbase);
            n = n.divide(bbase);
            x[i++] = alphabet.charAt(b.intValue());
        }
        x[i++] = alphabet.charAt(n.intValue());

        // pad with zeros-index value if necessary
        while (i < length) {
            x[i++] = alphabet.charAt(0);
        }
        return new String(x);
    }

    /**
     * Decode a base X string representation into an integer
     * @param str          the original string
     * @param alphabet     the alphabet and radix (len(alphabet)) for decoding
     * @return             an integer value of the encoded string
     */
    protected static BigInteger decode_int(String str, String alphabet) {

        int strlen = str.length();
        BigInteger base = BigInteger.valueOf(alphabet.length());
        BigInteger num = BigInteger.ZERO;
        int idx =0;
        for (char each : str.toCharArray()) {
            int exponent = (strlen - (idx + 1));
            num = num.add(base.pow(exponent).multiply(BigInteger.valueOf(alphabet.indexOf(each))));
            idx += 1;
        }
        return num;
    }

    /**
     * Return the canonical alphabet for a given base
     * @param base          a base
     * @return              the canonical alphabet for the base
     */
    protected static String alphabetForBase(int base) {
        switch (base) {
            case 10:
                return DIGITS;
            case 26:
                // used by NIST test vectors
                return DIGITS + "abcdefghijklmnop";
            case 36:
                return DIGITS + ASCII_UPPERCASE;
            case 64:
                return DIGITS + ASCII_UPPERCASE + ASCII_LOWERCASE;
            default:
                throw new RuntimeException("Unsupported radix");
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final int NUM_ROUNDS =   8;
    private static final int BLOCK_SIZE =   16;      // aes.BlockSize
    private static final int TWEAK_LEN =    8;       // Original FF3 64-bit tweak length
    private static final int TWEAK_LEN_NEW =  7;     // FF3-1 56-bit tweak length
    private static final int HALF_TWEAK_LEN = TWEAK_LEN/2;
    private static int MAX_RADIX =    256;
    private static final Logger logger = LogManager.getLogger(FF3Cipher.class.getName());

    /** The recommendation in Draft SP 800-38G was strengthened to a requirement in Draft SP 800-38G Revision 1:
       the minimum domain size for FF1 and FF3-1 is one million */
    public static int DOMAIN_MIN =  1000000;  // 1M
    public static final String DIGITS = ("0123456789");
    public static final String ASCII_LOWERCASE = ("abcdefghijklmnopqrstuvwxyz");
    public static final String ASCII_UPPERCASE = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    private final int radix;
    private final String alphabet;
    private byte[] tweakBytes;
    private final int minLen;
    private final int maxLen;
    private final Cipher aesCipher;
}
