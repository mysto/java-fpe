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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FF3Cipher {
    /**
     * Class FF3Cipher implements the FF3 format-preserving encryption algorithm with default
     * radix of 10.
     *
     * @param key         encryption key used to initialize AES ECB
     * @param tweak       used in each round and split into right and left sides
     */
    public FF3Cipher(String key, String tweak) {
        this(key, tweak, 10);
    }
    /**
     * Class FF3Cipher implements the FF3 format-preserving encryption algorithm
     *
     * @param key         encryption key used to initialize AES ECB
     * @param tweak       used in each round and split into right and left sides
     * @param radix       the domain of the alphabet, 10, 26 or 36
     */
    public FF3Cipher(String key, String tweak, int radix) {
        this.radix = radix;
        byte[] keyBytes = HexStringToByteArray(key);

        // Calculate range of supported message lengths [minLen..maxLen]
        // radix 10: 6 ... 56, 26: 5 ... 40, 36: 4 .. 36

        // Per revised spec, radix^minLength >= 1,000,000
        this.minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));

        // We simplify the specs log[radix](2^96) to 96/log2(radix) using the log base change rule
        this.maxLen = (int) (2 * Math.floor(Math.log(Math.pow(2,96))/Math.log(radix)));

        int keyLen = keyBytes.length;
        // Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
        if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
            throw new IllegalArgumentException("key length " + keyLen + " but must be 128, 192, or 256 bits");
        }

        // While FF3 allows radices in [2, 2^16], there is a practical limit to 36 (alphanumeric)
        // because Java BigInt only supports up to base 36.
        if ((radix < 2) || (radix > MAX_RADIX)) {
            throw new IllegalArgumentException ("radix must be between 2 and 36, inclusive");
        }

        // Make sure 2 <= minLength <= maxLength < 2*floor(log base radix of 2^96) is satisfied
        if ((this.minLen < 2) || (this.maxLen < this.minLen)) {
            throw new IllegalArgumentException ("minLen or maxLen invalid, adjust your radix");
        }

        this.tweakBytes = HexStringToByteArray(tweak);

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

    /* convenience method to override tweak */
    public String encrypt(String plaintext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = HexStringToByteArray(tweak);
        return encrypt(plaintext);
    }

    public String encrypt(String plaintext) throws BadPaddingException, IllegalBlockSizeException {
        int n = plaintext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Make sure the given the length of tweak in bits is 64
        if (this.tweakBytes.length != TWEAK_LEN){
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 8 bytes, or 64 bits",
                    this.tweakBytes.length));
        }

        // Check if the plaintext message is formatted in the current radix
        try {
            new BigInteger(plaintext, this.radix);
        } catch (NumberFormatException ex) {
            throw new NumberFormatException(String.format("The plaintext is not supported in the current radix %d", this.radix));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = plaintext.substring(0,u);
        String B = plaintext.substring(u);
        logger.info("r {} A {} B {}", this.radix, A, B);

        // Split the tweak
        logger.info("tweak: {}", byteArrayToHexString(this.tweakBytes));
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd

        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        logger.info("u {} v {} modU: {} modV: {}", u, v, modU, modV);
        logger.info("tL: {} tR: {}", byteArrayToHexString(Tl), byteArrayToHexString(Tr));

        for (byte i = 0; i < NUM_ROUNDS; ++ i) {
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
            P = calculateP( i, this.radix, W, B);

            // Calculate S by operating on P in place
            reverseBytes(P);
            byte[] S = this.aesCipher.doFinal(P);

            reverseBytes(S);
            logger.info("\tS: {}", byteArrayToHexString(S));

            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);

            // Calculate c
            try {
                c = new BigInteger(reverseString(A), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string A is not within base/radix");
            }

            c = c.add(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            logger.info("\tm: {} A: {} c: {} y: {}", m, A, c, y);

            // Convert c to sting using radix and length m
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());

            // Final steps
            A = B;
            B = C;
            logger.info("A: {} B: {}", A, B);
        }
        return A+B;
    }

    /* convenience method to override tweak */
    public String decrypt(String ciphertext, String tweak) throws BadPaddingException, IllegalBlockSizeException {
        this.tweakBytes = HexStringToByteArray(tweak);
        return decrypt(ciphertext);
    }

    public String decrypt(String ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        int n = ciphertext.length();

        // Check if message length is within minLength and maxLength bounds
        if ((n < this.minLen) || (n > this.maxLen)) {
            throw new IllegalArgumentException(String.format("message length %d is not within min %d and max %d bounds",
                    n, this.minLen, this.maxLen));
        }

        // Make sure the given the length of tweak in bits is 64
        if (this.tweakBytes.length != TWEAK_LEN){
            throw new IllegalArgumentException(String.format("tweak length %d is invalid: tweak must be 8 bytes, or 64 bits",
                    this.tweakBytes.length));
        }

        // Check if the ciphertext message is formatted in the current radix
        try {
            new BigInteger(ciphertext, this.radix);
        } catch (NumberFormatException ex) {
            throw new NumberFormatException(String.format("The plaintext is not supported in the current radix %d", this.radix));
        }

        // Calculate split point
        int u = (int) Math.ceil(n / 2.0);
        int v = n - u;

        // Split the message
        String A = ciphertext.substring(0,u);
        String B = ciphertext.substring(u);

        // Split the tweak
        logger.info("tweak: {}", byteArrayToHexString(this.tweakBytes));
        byte[] Tl = Arrays.copyOf(this.tweakBytes, HALF_TWEAK_LEN);
        byte[] Tr = Arrays.copyOfRange(this.tweakBytes, HALF_TWEAK_LEN, TWEAK_LEN);

        // P is always 16 bytes
        byte[] P;

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd

        BigInteger modU = BigInteger.valueOf(this.radix).pow(u);
        BigInteger modV = BigInteger.valueOf(this.radix).pow(v);
        logger.info("modU: {} modV: {}", modU, modV);
        logger.info("tL: {} tR: {}", byteArrayToHexString(Tl), byteArrayToHexString(Tr));

        for (byte i = (byte) (NUM_ROUNDS-1); i >= 0; --i) {
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
            P = calculateP( i, this.radix, W, A);

            // Calculate S by operating on P in place
            reverseBytes(P);
            byte[] S = this.aesCipher.doFinal(P);

            reverseBytes(S);
            logger.info("\tS: {}", byteArrayToHexString(S));

            BigInteger y = new BigInteger(byteArrayToHexString(S), 16);

            // Calculate c
            try {
                c = new BigInteger(reverseString(B), this.radix);
            } catch (NumberFormatException ex) {
                throw new RuntimeException("string B is not within base/radix");
            }

            c = c.subtract(y);

            if (i % 2 == 0) {
                c = c.mod(modU);
            } else {
                c = c.mod(modV);
            }

            logger.info("\tm: {} A: {} c: {} y: {}", m, A, c, y);

            // Convert c to sting using radix and length m
            String C = c.toString(this.radix);
            C = reverseString(C);
            C = C + "00000000".substring(0,m-C.length());

            // Final steps
            B = A;
            A = C;
            logger.info("A: {} B: {}", A, B);
        }
        return A+B;
    }

    protected static byte[] calculateP(int i, int radix, byte[] W, String B) {

        byte[] P = new byte[BLOCK_SIZE];     // P is always 16 bytes, zero initialized

        // Calculate P by XORing W, i into the first 4 bytes of P
        // i only requires 1 byte, rest are 0 padding bytes
        // Anything XOR 0 is itself, so only need to XOR the last byte

        P[0] = W[0];
        P[1] = W[1];
        P[2] = W[2];
        P[3] = (byte) (W[3] ^ i);

        // The remaining 12 bytes of P are copied from reverse(B) with padding

        B = reverseString(B);
        byte[] bBytes = new BigInteger(B, radix).toByteArray();

        System.arraycopy(bBytes,0,P,(BLOCK_SIZE-bBytes.length),bBytes.length);
        logger.info("round: {} W: {} P: {}", i, byteArrayToHexString(W), byteArrayToIntString(P));
        return P;
    }

    protected static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    /*
     * Reverse a byte array in-place
     */
    protected void reverseBytes(byte[] b) {
        for(int i=0; i<b.length/2; i++){
            byte temp = b[i];
            b[i] = b[b.length -i -1];
            b[b.length -i -1] = temp;
        }
    }

    protected static byte[] HexStringToByteArray(String s) {
        byte[] data = new byte[s.length()/2];
        for(int i=0;i < s.length();i+=2) {
            data[i/2] = (Integer.decode("0x"+s.charAt(i)+s.charAt(i+1))).byteValue();
        }
        return data;
    }

    /*
     * used for debugging
     * Java 17 has java.util.HexFormat
     */
    protected static String byteArrayToHexString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            String aByte = String.format("%02X", b);
            sb.append(aByte);
        }
        return sb.toString();
    }
    protected static String byteArrayToIntString(byte[] byteArray){

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (byte b : byteArray) {
            // cast signed byte to int and mask for last byte
            String aByte = String.format("%d ", ((int) b) & 0xFF);
            sb.append(aByte);
        }
        sb.append(']');
        return sb.toString();
    }


    public static int DOMAIN_MIN =  1000000;  // 1M is currently recommended in FF3-1
    public static int NUM_ROUNDS =   8;
    public static int BLOCK_SIZE =   16;      // aes.BlockSize
    public static int TWEAK_LEN =    8;       // TODO: change to 7 bytes when 56-bit test vectors for FF3-1 become available
    public static int HALF_TWEAK_LEN = TWEAK_LEN/2;
    public static int MAX_RADIX =    36;      // supports radix 2..36
    public static Logger logger = LogManager.getLogger(FF3Cipher.class.getName());

    private final int radix;
    private byte[] tweakBytes;
    private final int minLen;
    private final int maxLen;
    private final Cipher aesCipher;
}
