[![Build Status](https://github.com/mysto/java-fpe/actions/workflows/build-gradle.yml/badge.svg)](https://github.com/mysto/java-fpe/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.mysto/ff3/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.mysto/ff3) 
[![javadoc](https://javadoc.io/badge2/io.github.mysto/ff3/javadoc.svg)](https://javadoc.io/doc/io.github.mysto/ff3)

<p align="center">
  <a href="https://privacylogistics.com/">
    <img
      alt="Mysto"
      src="https://privacylogistics.com/Mysto-logo.jpg"
    />
  </a>
</p>

# ff3 - Format Preserving Encryption in Java

An implementation of the NIST approved FF3 and FF3-1 Format Preserving Encryption (FPE) algorithms in Java.

This package follows the FF3 algorithm for Format Preserving Encryption as described in the March 2016 NIST publication 800-38G _Methods for Format-Preserving Encryption_, 
and revised on February 28th, 2019 with a draft update for FF3-1.

* [NIST Recommendation SP 800-38G (FF3)](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST Recommendation SP 800-38G Revision 1 (FF3-1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)
* [NIST SP 800-38G Revision 1 (2nd Public Draft)](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd)

**NOTE:** NIST's Feburary 2025 Draft 2 has removed FF3 from the NIST standard. Contact me about a licensed version of FF1 in Java.

Changes to minimum domain size and revised tweak length have been implemented in this package with
both 64-bit and 56-bit tweaks are supported. NIST has only published official test vectors for 64-bit tweaks, but draft ACVP test vectors have been used for testing FF3-1. It is expected the final
NIST standard will provide updated test vectors with 56-bit tweak lengths.

## Use

To use the package, you need to use following Maven dependency:

```maven
<dependency>
    <groupId>io.github.mysto</groupId>
    <artifactId>ff3</artifactId>
    <version>1.0</version>
</dependency>
```
or Gradle Kotlin:

```gradle
implementation("io.github.mysto:ff3:1.0")
```
or simply download jars from the Maven Central repository.

This package has external dependencies only on Log4j and testing (which uses JUnit).

## Usage

FF3 is a Feistel cipher, and Feistel ciphers are initialized with a radix representing an alphabet. The number of 
characters in an alphabet is called the _radix_. The following radix values are common:
* radix 10: digits 0..9
* radix 36: alphanumeric 0..9, a-z
* radix 62: alphanumeric 0..9, a-z, A-Z

Special characters and international character sets, such as those found in UTF-8, would require a larger radix, and are not supported.
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of a letter followed
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):
* radix 10: 56
* radix 36: 36
* radix 62: 32

To work around string length, its possible to encode longer text in chunks.

The key length must be 128, 192, or 256 bits in length. The tweak is 7 bytes (FF3-1) or 8 bytes for the origingal FF3.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not store the key in memory after initializing the cipher.

## Code Example

The example code below can help you get started.

Using default domain [0-9]

```jshell
   jshell --class-path build/libs/ff3-X.X.jar:~/lib/log4j-core-2.24.3.jar:~/lib/log4j-api-2.24.3.jar

    import com.privacylogistics.FF3Cipher;
    FF3Cipher c = new FF3Cipher("2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564");
    String pt = "3992520240";
    String ciphertext = c.encrypt(pt);
    String plaintext = c.decrypt(ciphertext);
    pt;ciphertext;plaintext
```

to enable TRACE level messages:
```jshell
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.Level;
Logger logger = LogManager.getRootLogger();
Configurator.setRootLevel(Level.TRACE);

```

## Custom alphabets

Custom alphabets up to 256 characters are supported. To use an alphabet consisting of the uppercase letters A-F (radix=6), we can continue
from the above code example with:

```java
FF3Cipher c6 = new FF3Cipher(key, tweak, "ABCDEF");
String plaintext = "BADDCAFE";
String ciphertext = c6.encrypt(plaintext);
String decrypted = c6.decrypt(ciphertext);

System.out(String.format("{%s} -> {%s} -> {%s}", plaintext, ciphertext, decrypted);
```


## The FF3 Algorithm

The FF3 algorithm is a tweakable block cipher based on an eight round Feistel cipher. A block cipher operates on fixed-length groups of bits, called blocks. A Feistel Cipher is not a specific cipher,
but a design model.  This FF3 Feistel encryption consisting of eight rounds of processing
the plaintext. Each round applies an internal function or _round function_, followed by transformation steps.

The FF3 round function uses AES encryption in ECB mode, which is performed each iteration 
on alternating halves of the text being encrypted. The *key* value is used only to initialize the AES cipher. Thereafter
the *tweak* is used together with the intermediate encrypted text as input to the round function.

FF3 uses a single-block encryption with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `FF3Cipher.java`. 
FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

## Other FPE Algorithms

Only FF1 and FF3 have been approved by NIST for format preserving encryption. There are patent claims on FF1 which allegedly include open source implementations. Given the issues raised in ["The Curse of Small Domains: New Attacks on Format-Preserving Encryption"](https://eprint.iacr.org/2018/556.pdf) by Hoang, Tessaro and Trieu in 2018, it is prudent to be very cautious about using any FPE that isn't a standard and hasn't stood up to public scrutiny.

## Build & Testing

Build this project with gradle:

`gradle build`

Official [test vectors](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/ff3samples.pdf) for FF3 provided by NIST,
are used for testing in this package. Also included are draft ACVP test vectors for FF3-1 with 56-bit tweaks.

To run the unit tests, including all test vectors from the NIST specification, run the command:

`gradle test`

## Performance Benchmarks

Mysto FF3 was benchmarked on a MacBook Air M2 performing 105,000 tokenization per second with mixed 8 character data input.

To run the performance tests:

`gradle jmh`

(Note: running jmh requires uncommenting jmh in the build.gradle.kts) 

## Requires

This project was built and tested with Java 8 and 11.  It uses the javax.crypto for AES encryption in ECB mode.

## Implementation Notes

This implementation follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

FPE can be used for sensitive data tokenization, especially with PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

The tweak is required in the initial `FF3Cipher` constructor, but can optionally be overridden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
