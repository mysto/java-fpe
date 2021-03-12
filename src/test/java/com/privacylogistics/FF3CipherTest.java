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

public class FF3CipherTest {
    @Test
    public void testCreate() throws Exception {
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
        Assert.assertNotNull(c);
    }
    @Test
    public void testCalculateP() {
        // NIST Sample #1, round 0
        int i=0, m=9, radix=10;
        String B = "567890000";
        byte[] W = FF3Cipher.HexStringToByteArray("FA330A73");
        byte[] P = FF3Cipher.calculateP(i, radix, W, B);
        Assert.assertArrayEquals(P, new byte[]
                {(byte) 250, 51, 10, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 129, (byte) 205});
    }

    /*
     * NIST Test Vectors for 128, 198, and 256 bit modes
     * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf
     */

    // AES-128

    @Test
    public void test128dot1() throws Exception {
        // Sample #1 from NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
        String pt = "890121234567890000", ct = "750918814058654607";
        String ciphertext = c.encrypt(pt);
        Assert.assertEquals(ct, ciphertext);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test128dot2() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8");
        String pt = "890121234567890000", ct = "018989839189395384";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test128dot3() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
        String pt = "89012123456789000000789000000", ct = "48598367162252569629397416226";
        String ciphertext = c.encrypt(pt);
        Assert.assertEquals(ct, ciphertext);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test128dot4() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "0000000000000000");
        String pt = "89012123456789000000789000000", ct = "34695224821734535122613701434";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
         Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test128dot5() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(26, "EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8");
        String pt = "0123456789abcdefghi", ct = "g2pk40i992fn20cjakb";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }

    // AES-192

    @Test
    public void test192dot1() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73");
        String pt = "890121234567890000", ct = "646965393875028755";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test192dot2() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8");
        String pt = "890121234567890000", ct = "961610514491424446";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test192dot3() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73");
        String pt = "89012123456789000000789000000", ct = "53048884065350204541786380807";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test192dot4() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "0000000000000000");
        String pt = "89012123456789000000789000000", ct = "98083802678820389295041483512";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test192dot5() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8");
        String pt = "0123456789abcdefghi", ct = "i0ihe2jfj7a9opf9p88";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }

    // AES-256

    @Test
    public void test256dot1() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73");
        String pt = "890121234567890000", ct = "922011205562777495";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test256dot2() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8");
        String pt = "890121234567890000", ct = "504149865578056140";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test256dot3() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73");
        String pt = "89012123456789000000789000000", ct = "04344343235792599165734622699";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test256dot4() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "0000000000000000");
        String pt = "89012123456789000000789000000", ct = "30859239999374053872365555822";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
    @Test
    public void test256dot5() throws Exception {
        // NIST FF3-AES128
        FF3Cipher c = new FF3Cipher(26, "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8");
        String pt = "0123456789abcdefghi", ct = "p0b2godfja9bhb7bk38";
        String ciphertext = c.encrypt(pt);
        String plaintext = c.decrypt(ciphertext);
        Assert.assertEquals(ct, ciphertext);
        Assert.assertEquals(pt, plaintext);
    }
}
