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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.condition.JRE;

import java.math.BigInteger;

import static com.privacylogistics.FF3Cipher.reverseString;
import static com.privacylogistics.FF3Cipher.encode_int_r;
import static com.privacylogistics.FF3Cipher.decode_int;
import static com.privacylogistics.FF3Cipher.hexStringToByteArray;

public class FF3CipherTest {

    /*
     * NIST Test Vectors for 128, 198, and 256 bit modes
     * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf
     */

    static int Tradix=0, Tkey=1, Ttweak=2, Tplaintext=3, Tciphertext=4;

    static String[][] TestVectors = {
            // AES-128 - radix, key, tweak, plaintext, ciphertext
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73",
                    "890121234567890000", "750918814058654607"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8",
                    "890121234567890000", "018989839189395384"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73",
                    "89012123456789000000789000000", "48598367162252569629397416226"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A94", "0000000000000000",
                    "89012123456789000000789000000", "34695224821734535122613701434"
            },
            { "26", "EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8",
                    "0123456789abcdefghi", "g2pk40i992fn20cjakb"
            },

            // AES-192 - radix, key, tweak, plaintext, ciphertext
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73",
                    "890121234567890000", "646965393875028755"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8",
                    "890121234567890000", "961610514491424446"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73",
                    "89012123456789000000789000000", "53048884065350204541786380807"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "0000000000000000",
                    "89012123456789000000789000000", "98083802678820389295041483512"
            },
            { "26", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8",
                    "0123456789abcdefghi", "i0ihe2jfj7a9opf9p88"
            },

            // AES-256 - radix, key, tweak, plaintext, ciphertext
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73",
                    "890121234567890000", "922011205562777495"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8",
                    "890121234567890000", "504149865578056140"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73",
                    "89012123456789000000789000000", "04344343235792599165734622699"
            },
            { "10", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "0000000000000000",
                    "89012123456789000000789000000", "30859239999374053872365555822"
            },
            { "26", "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8",
                    "0123456789abcdefghi", "p0b2godfja9bhb7bk38"
            }
        };

    static int Uradix=0, Ualphabet=1, Ukey=2, Utweak=3, Uplaintext=4, Uciphertext=5;

    static String[][] TestVectors_ACVP_AES_FF3_1 = {
            // AES-128 tg: 1-3 tc: 1-2  radix, alphabet, key, tweak, plaintext, ciphertext
            {"10", "0123456789", "2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564",
                    "3992520240", "8901801106"
            },
            {"10", "0123456789", "01C63017111438F7FC8E24EB16C71AB5", "C4E822DCD09F27",
                    "60761757463116869318437658042297305934914824457484538562",
                    "35637144092473838892796702739628394376915177448290847293"
            },
            {"26", "abcdefghijklmnopqrstuvwxyz", "718385E6542534604419E83CE387A437", "B6F35084FA90E1",
                    "wfmwlrorcd", "ywowehycyd"
            },
            {"26", "abcdefghijklmnopqrstuvwxyz", "DB602DFF22ED7E84C8D8C865A941A238", "EBEFD63BCC2083",
                    "kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm",
                    "belcfahcwwytwrckieymthabgjjfkxtxauipmjja"
            },
            {"64", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/", "AEE87D0D485B3AFD12BD1E0B9D03D50D",
                    "5F9140601D224B",
                    "ixvuuIHr0e", "GR90R1q838"
            },
            {"64", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/", "7B6C88324732F7F4AD435DA9AD77F917",
                    "3F42102C0BAB39",
                    "21q1kbbIVSrAFtdFWzdMeIDpRqpo", "cvQ/4aGUV4wRnyO3CHmgEKW5hk8H"
            }
    };

    @Test
    public void testConstructors() {
        String keyStr = "EF4359D8D580AA4F7F036D6F04FC6A94";
        String tweakStr = "D8E7920AFA330A73";
        byte[] keyBytes = hexStringToByteArray(keyStr);
        byte[] tweakBytes = hexStringToByteArray(tweakStr);

        FF3Cipher cs0 = new FF3Cipher(keyStr, tweakStr);
        FF3Cipher cs1 = new FF3Cipher(keyStr, tweakStr, 62);
        FF3Cipher cs2 = new FF3Cipher(keyStr, tweakStr, "0123456789");
        FF3Cipher cb0 = new FF3Cipher(keyBytes, tweakBytes);
        FF3Cipher cb1 = new FF3Cipher(keyBytes, tweakBytes, 62);
        FF3Cipher cb2 = new FF3Cipher(keyBytes, tweakBytes, "0123456789");

        assertNotNull(cs0);
        assertNotNull(cs1);
        assertNotNull(cs2);
        assertNotNull(cb0);
        assertNotNull(cb1);
        assertNotNull(cb2);
    }

    @Test
    public void testByteArrayUtils() {
        String hexstr = "BADA55";
        byte[] bytestr = {(byte) 0xba, (byte) 0xda, (byte) 0x55};
        byte[] hex = FF3Cipher.hexStringToByteArray(hexstr);
        assertArrayEquals(hex, bytestr);
        String str = FF3Cipher.byteArrayToHexString(hex);
        assertEquals(hexstr, str);
    }

    @Test
    public void testCalculateP() {
        // NIST Sample #1, round 0
        int i = 0;
        String alphabet = "0123456789";
        String B = "567890000";
        byte[] W = FF3Cipher.hexStringToByteArray("FA330A73");
        byte[] P = FF3Cipher.calculateP(i, alphabet, W, B);
        assertArrayEquals(P, new byte[]
                {(byte) 250, 51, 10, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 129, (byte) 205});
    }

    /*
    ToDo: replace this with a value-not-in radix error
    @Test(expected = NumberFormatException.class)
    public void testInvalidPlaintext() throws Exception {
        FF3Cipher c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10);
        c.encrypt("222-22-2222");
    }*/

    @Test
    public void testEncodeBigInt() {
        assertEquals("101", reverseString(encode_int_r(BigInteger.valueOf(5), "01", 3)));
        assertEquals("11", reverseString(encode_int_r(BigInteger.valueOf(6), "01234", 2)));
        assertEquals("00012", reverseString(encode_int_r(BigInteger.valueOf(7), "01234", 5)));
        assertEquals("a", reverseString(encode_int_r(BigInteger.valueOf(10), "0123456789abcdef", 1)));
        assertEquals("20", reverseString(encode_int_r(BigInteger.valueOf(32), "0123456789abcdef", 2)));
    }

    @Test
    public void testDecodeInt() {
        assertEquals(BigInteger.valueOf(321), (decode_int("321", "0123456789")));
        assertEquals(BigInteger.valueOf(101), (decode_int("101", "0123456789")));
        assertEquals(BigInteger.valueOf(101), (decode_int("00101", "0123456789")));
        assertEquals(BigInteger.valueOf(0x02), (decode_int("02", "0123456789abcdef")));
        assertEquals(BigInteger.valueOf(0xAA), (decode_int("aa", "0123456789abcdef")));
        assertEquals(new BigInteger("2658354847544284194395037922"), (decode_int("2658354847544284194395037922", "0123456789")));
    }

    @Test
    public void testNistFF3() throws Exception {
        // NIST FF3-AES 128, 192, 256
        for( String[] testVector : TestVectors) {
            // NIST radix to alphabet mappings are non-standard, so we special case them here
            FF3Cipher c;
            int r = Integer.parseInt(testVector[Tradix]);
            switch (r) {
                case 2:
                    c = new FF3Cipher(testVector[Tkey], testVector[Ttweak], 2);
                    break;
                case 10:
                    c = new FF3Cipher(testVector[Tkey], testVector[Ttweak], 10);
                    break;
                case 26:
                    c = new FF3Cipher(testVector[Tkey], testVector[Ttweak], FF3Cipher.DIGITS + "abcdefghijklmnop");
                    break;
                default:
                    throw new RuntimeException(String.format("Unsupported radix %d", r));
            }
            String pt = testVector[Tplaintext], ct = testVector[Tciphertext];
            String ciphertext = c.encrypt(pt);
            String plaintext = c.decrypt(ciphertext);
            assertEquals(ct, ciphertext);
            assertEquals(pt, plaintext);
        }
    }

    @Test
    public void testAcvpFF3_1() throws Exception {
        // ACVP FF3-AES 128, 192, 256
        for( String[] testVector : TestVectors_ACVP_AES_FF3_1) {
            int radix = Integer.parseInt(testVector[Uradix]);
            FF3Cipher c;
            if (radix == 10) {
                c = new FF3Cipher(testVector[Ukey], testVector[Utweak], radix);
            } else {
                c = new FF3Cipher(testVector[Ukey], testVector[Utweak], testVector[Ualphabet]);
            }
            String pt = testVector[Uplaintext], ct = testVector[Uciphertext];
            String ciphertext = c.encrypt(pt);
            String plaintext = c.decrypt(ciphertext);
            assertEquals(ct, ciphertext);
            assertEquals(pt, plaintext);
        }
    }

    @Test
    public void testFF3_1() throws Exception {
        // Test with 56 bit tweak
        String[] testVector = TestVectors[0];
        FF3Cipher c = new FF3Cipher(testVector[Tkey], "D8E7920AFA330A", Integer.parseInt(testVector[Tradix]));
        String pt = testVector[Tplaintext], ct = "477064185124354662";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        assertEquals(ct, ciphertext);
        assertEquals(pt, plaintext);
    }

    @Test
    @EnabledOnJre(value = JRE.JAVA_11)
    public void testCustomAlphabet() throws Exception {
        // Check the first NIST 128-bit test vector using superscript characters
        String alphabet = "⁰¹²³⁴⁵⁶⁷⁸⁹";
        String key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        String tweak = "D8E7920AFA330A73";
        String pt = "⁸⁹⁰¹²¹²³⁴⁵⁶⁷⁸⁹⁰⁰⁰⁰";
        String ct = "⁷⁵⁰⁹¹⁸⁸¹⁴⁰⁵⁸⁶⁵⁴⁶⁰⁷";
        FF3Cipher c = new FF3Cipher(key, tweak, alphabet);
        String ciphertext = c.encrypt(pt);
        assertEquals(ct, ciphertext) ;
        String plaintext = c.decrypt(ciphertext);
        assertEquals(pt, plaintext);
    }

    @Test
    public void testGermanAlphabet() throws Exception {
        // Test the German alphabet with a radix of 70.  German consists of the latin alphabet
        // plus four additional letters, each of which have uppercase and lowercase letters

        String german_alphabet = FF3Cipher.DIGITS + FF3Cipher.ASCII_LOWERCASE + FF3Cipher.ASCII_UPPERCASE + "ÄäÖöÜüẞß";
        String key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        String tweak = "D8E7920AFA330A73";
        String pt = "liebeGrüße";
        String ct = "5kÖQbairXo";
        FF3Cipher c = new FF3Cipher(key, tweak, german_alphabet);
        String ciphertext = c.encrypt(pt);
        assertEquals(ct, ciphertext);
        String plaintext = c.decrypt(ciphertext);
        assertEquals(pt, plaintext);
    }

    @Test
    void testTweakHasNoSideEffects() throws Exception {
        String key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        String tweak = "D8E7920AFA330A73";
        String tweak2 = "0000000000000000";
        String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        FF3Cipher c = new FF3Cipher(key, tweak, alphabet);
        String pt = "Foobar";

        String ciphertext1 = c.encrypt(pt);
        String ciphertext2 = c.encrypt(pt, tweak);
        assertEquals(ciphertext1, ciphertext2);

        String ciphertext3 = c.encrypt(pt, tweak2); // this will NOT overwrite the initial tweak
        assertNotEquals(ciphertext1, ciphertext3); // different ciphertexts because different tweaks were used

        String ciphertext4 = c.encrypt(pt); // will still use the initial tweak
        assertEquals(ciphertext1, ciphertext4);
    }
}
