package com.privacylogistics;

/**
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

import org.junit.Test;
import org.junit.Assert;
import java.math.BigInteger;

import static com.privacylogistics.FF3Cipher.reverseString;
import static com.privacylogistics.FF3Cipher.encode_int_r;
import static com.privacylogistics.FF3Cipher.decode_int_r;

public class FF3CipherTest {

    /*
     * NIST Test Vectors for 128, 198, and 256 bit modes
     * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf
     */

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

    static int Tradix=0, Tkey=1, Ttweak=2, Tplaintext=3, Tciphertext=4;

    @Test
    public void testCreate() throws Exception {
        FF3Cipher c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
        Assert.assertNotNull(c);
    }

    @Test
    public void testByteArrayUtils() {
        String hexstr = "BADA55";
        byte[] bytestr = {(byte) 0xba, (byte) 0xda, (byte) 0x55};
        byte[] hex = FF3Cipher.hexStringToByteArray(hexstr);
        Assert.assertArrayEquals(hex, bytestr);
        String str = FF3Cipher.byteArrayToHexString(hex);
        Assert.assertEquals(hexstr, str);
    }

    @Test
    public void testCalculateP() {
        // NIST Sample #1, round 0
        int i = 0, radix = 10;
        String B = "567890000";
        byte[] W = FF3Cipher.hexStringToByteArray("FA330A73");
        byte[] P = FF3Cipher.calculateP(i, radix, W, B);
        Assert.assertArrayEquals(P, new byte[]
                {(byte) 250, 51, 10, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 129, (byte) 205});
    }

    @Test(expected = NumberFormatException.class)
    public void testInvalidPlaintext() throws Exception {
        FF3Cipher c = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10);
        c.encrypt("222-22-2222");
    }

    @Test
    public void testEncodeInt() throws Exception {
        Assert.assertEquals("101", reverseString(encode_int_r(5, 2, 3)));
        Assert.assertEquals("11", reverseString(encode_int_r(6, 5, 2)));
        Assert.assertEquals("00012", reverseString(encode_int_r(7, 5, 5)));
        Assert.assertEquals("a", reverseString(encode_int_r(10, 16, 1)));
        Assert.assertEquals("20", reverseString(encode_int_r(32, 16, 2)));
    }

    @Test
    public void testDecodeInt() throws Exception {
        Assert.assertEquals(BigInteger.valueOf(321), (decode_int_r("123", 10)));
        Assert.assertEquals(BigInteger.valueOf(101), (decode_int_r("101", 10)));
        Assert.assertEquals(BigInteger.valueOf(0x02), (decode_int_r("20", 16)));
        Assert.assertEquals(BigInteger.valueOf(0xAA), (decode_int_r("aa", 16)));
    }



    @Test
    public void testNistFF3() throws Exception {
        // NIST FF3-AES 128, 192, 256
        for( String[] testVector : TestVectors) {
            FF3Cipher c = new FF3Cipher(testVector[Tkey], testVector[Ttweak], Integer.valueOf(testVector[Tradix]));
            String pt = testVector[Tplaintext], ct = testVector[Tciphertext];
            String ciphertext = c.encrypt(pt);
            String plaintext = c.decrypt(ciphertext);
            Assert.assertEquals(ct, ciphertext);
            Assert.assertEquals(pt, plaintext);
        }
    }

    @Test
    public void testFF3_1() throws Exception {
        // Experimental test with 56 bit tweak
        String[] testVector = TestVectors[0];
        FF3Cipher c = new FF3Cipher(testVector[Tkey], "D8E7920AFA330A", Integer.valueOf(testVector[Tradix]));
        String pt = testVector[Tplaintext], ct = "477064185124354662";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
}
