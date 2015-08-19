/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/OpenSSL.java $
 * $Revision: 144 $
 * $Date: 2009-05-25 11:14:29 -0700 (Mon, 25 May 2009) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import org.apache.kerby.util.Base64;
import org.apache.kerby.util.Base64InputStream;
import org.apache.kerby.util.Hex;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.StringTokenizer;

/**
 * Class for encrypting or decrypting data with a password (PBE - password
 * based encryption).  Compatible with "openssl enc" unix utility.  An OpenSSL
 * compatible cipher name must be specified along with the password (try "man enc" on a
 * unix box to see what's possible).  Some examples:
 * <ul><li>des, des3, des-ede3-cbc
 * <li>aes128, aes192, aes256, aes-256-cbc
 * <li>rc2, rc4, bf</ul>
 * <pre>
 * <em style="color: green;">// Encrypt!</em>
 * byte[] encryptedData = OpenSSL.encrypt( "des3", password, data );
 * </pre>
 * <p/>
 * If you want to specify a raw key and iv directly (without using PBE), use
 * the methods that take byte[] key, byte[] iv.  Those byte[] arrays can be
 * the raw binary, or they can be ascii (hex representation: '0' - 'F').  If
 * you want to use PBE to derive the key and iv, then use the methods that
 * take char[] password.
 * <p/>
 * This class is able to decrypt files encrypted with "openssl" unix utility.
 * <p/>
 * The "openssl" unix utility is able to decrypt files encrypted by this class.
 * <p/>
 * This class is also able to encrypt and decrypt its own files.
 *
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@gmail.com</a>
 * @since 18-Oct-2007
 */
public class OpenSSL {


    /**
     * Decrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher    The OpenSSL compatible cipher to use (try "man enc" on a
     *                  unix box to see what's possible).  Some examples:
     *                  <ul><li>des, des3, des-ede3-cbc
     *                  <li>aes128, aes192, aes256, aes-256-cbc
     *                  <li>rc2, rc4, bf</ul>
     * @param pwd       password to use for this PBE decryption
     * @param encrypted byte array to decrypt.  Can be raw, or base64.
     * @return decrypted bytes
     * @throws java.io.IOException              problems with encrypted bytes (unlikely!)
     * @throws java.security.GeneralSecurityException problems decrypting
     */
    public static byte[] decrypt(String cipher, char[] pwd, byte[] encrypted)
        throws IOException, GeneralSecurityException {
        ByteArrayInputStream in = new ByteArrayInputStream(encrypted);
        InputStream decrypted = decrypt(cipher, pwd, in);
        return Util.streamToBytes(decrypted);
    }

    /**
     * Decrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher    The OpenSSL compatible cipher to use (try "man enc" on a
     *                  unix box to see what's possible).  Some examples:
     *                  <ul><li>des, des3, des-ede3-cbc
     *                  <li>aes128, aes192, aes256, aes-256-cbc
     *                  <li>rc2, rc4, bf</ul>
     * @param pwd       password to use for this PBE decryption
     * @param encrypted InputStream to decrypt.  Can be raw, or base64.
     * @return decrypted bytes as an InputStream
     * @throws java.io.IOException              problems with InputStream
     * @throws java.security.GeneralSecurityException problems decrypting
     */
    public static InputStream decrypt(String cipher, char[] pwd,
                                      InputStream encrypted)
        throws IOException, GeneralSecurityException {
        CipherInfo cipherInfo = lookup(cipher);
        boolean salted = false;

        // First 16 bytes of raw binary will hopefully be OpenSSL's
        // "Salted__[8 bytes of hex]" thing.  Might be in Base64, though.
        byte[] saltLine = Util.streamToBytes(encrypted, 16);
        if (saltLine.length <= 0) {
            throw new IOException("encrypted InputStream is empty");
        }
        String firstEightBytes = "";
        if (saltLine.length >= 8) {
            firstEightBytes = new String(saltLine, 0, 8);
        }
        if ("SALTED__".equalsIgnoreCase(firstEightBytes)) {
            salted = true;
        } else {
            // Maybe the reason we didn't find the salt is because we're in
            // base64.
            if (Base64.isArrayByteBase64(saltLine)) {
                InputStream head = new ByteArrayInputStream(saltLine);
                // Need to put that 16 byte "saltLine" back into the Stream.
                encrypted = new ComboInputStream(head, encrypted);
                encrypted = new Base64InputStream(encrypted);
                saltLine = Util.streamToBytes(encrypted, 16);

                if (saltLine.length >= 8) {
                    firstEightBytes = new String(saltLine, 0, 8);
                }
                if ("SALTED__".equalsIgnoreCase(firstEightBytes)) {
                    salted = true;
                }
            }
        }

        byte[] salt = null;
        if (salted) {
            salt = new byte[8];
            System.arraycopy(saltLine, 8, salt, 0, 8);
        } else {
            // Encrypted data wasn't salted.  Need to put the "saltLine" we
            // extracted back into the stream.
            InputStream head = new ByteArrayInputStream(saltLine);
            encrypted = new ComboInputStream(head, encrypted);
        }

        int keySize = cipherInfo.keySize;
        int ivSize = cipherInfo.ivSize;
        boolean des2 = cipherInfo.des2;
        DerivedKey dk = deriveKey(pwd, salt, keySize, ivSize, des2);
        Cipher c = PKCS8Key.generateCipher(
            cipherInfo.javaCipher, cipherInfo.blockMode, dk, des2, null, true
        );

        return new CipherInputStream(encrypted, c);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher The OpenSSL compatible cipher to use (try "man enc" on a
     *               unix box to see what's possible).  Some examples:
     *               <ul><li>des, des3, des-ede3-cbc
     *               <li>aes128, aes192, aes256, aes-256-cbc
     *               <li>rc2, rc4, bf</ul>
     * @param pwd    password to use for this PBE encryption
     * @param data   byte array to encrypt
     * @return encrypted bytes as an array in base64.  First 16 bytes include the
     *         special OpenSSL "Salted__" info encoded into base64.
     * @throws java.io.IOException              problems with the data byte array
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static byte[] encrypt(String cipher, char[] pwd, byte[] data)
        throws IOException, GeneralSecurityException {
        // base64 is the default output format.
        return encrypt(cipher, pwd, data, true);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher The OpenSSL compatible cipher to use (try "man enc" on a
     *               unix box to see what's possible).  Some examples:
     *               <ul><li>des, des3, des-ede3-cbc
     *               <li>aes128, aes192, aes256, aes-256-cbc
     *               <li>rc2, rc4, bf</ul>
     * @param pwd    password to use for this PBE encryption
     * @param data   InputStream to encrypt
     * @return encrypted bytes as an InputStream.  First 16 bytes include the
     *         special OpenSSL "Salted__" info encoded into base64.
     * @throws java.io.IOException              problems with the data InputStream
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static InputStream encrypt(String cipher, char[] pwd,
                                      InputStream data)
        throws IOException, GeneralSecurityException {
        // base64 is the default output format.
        return encrypt(cipher, pwd, data, true);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher   The OpenSSL compatible cipher to use (try "man enc" on a
     *                 unix box to see what's possible).  Some examples:
     *                 <ul><li>des, des3, des-ede3-cbc
     *                 <li>aes128, aes192, aes256, aes-256-cbc
     *                 <li>rc2, rc4, bf</ul>
     * @param pwd      password to use for this PBE encryption
     * @param data     byte array to encrypt
     * @param toBase64 true if resulting InputStream should contain base64,
     *                 <br>false if InputStream should contain raw binary.
     * @return encrypted bytes as an array.  First 16 bytes include the
     *         special OpenSSL "Salted__" info.
     * @throws java.io.IOException              problems with the data byte array
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static byte[] encrypt(String cipher, char[] pwd, byte[] data,
                                 boolean toBase64)
        throws IOException, GeneralSecurityException {
        // we use a salt by default.
        return encrypt(cipher, pwd, data, toBase64, true);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher   The OpenSSL compatible cipher to use (try "man enc" on a
     *                 unix box to see what's possible).  Some examples:
     *                 <ul><li>des, des3, des-ede3-cbc
     *                 <li>aes128, aes192, aes256, aes-256-cbc
     *                 <li>rc2, rc4, bf</ul>
     * @param pwd      password to use for this PBE encryption
     * @param data     InputStream to encrypt
     * @param toBase64 true if resulting InputStream should contain base64,
     *                 <br>false if InputStream should contain raw binary.
     * @return encrypted bytes as an InputStream.  First 16 bytes include the
     *         special OpenSSL "Salted__" info.
     * @throws java.io.IOException              problems with the data InputStream
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static InputStream encrypt(String cipher, char[] pwd,
                                      InputStream data, boolean toBase64)
        throws IOException, GeneralSecurityException {
        // we use a salt by default.
        return encrypt(cipher, pwd, data, toBase64, true);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher   The OpenSSL compatible cipher to use (try "man enc" on a
     *                 unix box to see what's possible).  Some examples:
     *                 <ul><li>des, des3, des-ede3-cbc
     *                 <li>aes128, aes192, aes256, aes-256-cbc
     *                 <li>rc2, rc4, bf</ul>
     * @param pwd      password to use for this PBE encryption
     * @param data     byte array to encrypt
     * @param toBase64 true if resulting InputStream should contain base64,
     *                 <br>false if InputStream should contain raw binary.
     * @param useSalt  true if a salt should be used to derive the key.
     *                 <br>false otherwise.  (Best security practises
     *                 always recommend using a salt!).
     * @return encrypted bytes as an array.  First 16 bytes include the
     *         special OpenSSL "Salted__" info if <code>useSalt</code> is true.
     * @throws java.io.IOException              problems with the data InputStream
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static byte[] encrypt(String cipher, char[] pwd, byte[] data,
                                 boolean toBase64, boolean useSalt)
        throws IOException, GeneralSecurityException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        InputStream encrypted = encrypt(cipher, pwd, in, toBase64, useSalt);
        return Util.streamToBytes(encrypted);
    }

    /**
     * Encrypts data using a password and an OpenSSL compatible cipher
     * name.
     *
     * @param cipher   The OpenSSL compatible cipher to use (try "man enc" on a
     *                 unix box to see what's possible).  Some examples:
     *                 <ul><li>des, des3, des-ede3-cbc
     *                 <li>aes128, aes192, aes256, aes-256-cbc
     *                 <li>rc2, rc4, bf</ul>
     * @param pwd      password to use for this PBE encryption
     * @param data     InputStream to encrypt
     * @param toBase64 true if resulting InputStream should contain base64,
     *                 <br>false if InputStream should contain raw binary.
     * @param useSalt  true if a salt should be used to derive the key.
     *                 <br>false otherwise.  (Best security practises
     *                 always recommend using a salt!).
     * @return encrypted bytes as an InputStream.  First 16 bytes include the
     *         special OpenSSL "Salted__" info if <code>useSalt</code> is true.
     * @throws java.io.IOException              problems with the data InputStream
     * @throws java.security.GeneralSecurityException problems encrypting
     */
    public static InputStream encrypt(String cipher, char[] pwd,
                                      InputStream data, boolean toBase64,
                                      boolean useSalt)
        throws IOException, GeneralSecurityException {
        CipherInfo cipherInfo = lookup(cipher);
        byte[] salt = null;
        if (useSalt) {
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
            salt = new byte[8];
            rand.nextBytes(salt);
        }

        int keySize = cipherInfo.keySize;
        int ivSize = cipherInfo.ivSize;
        boolean des2 = cipherInfo.des2;
        DerivedKey dk = deriveKey(pwd, salt, keySize, ivSize, des2);
        Cipher c = PKCS8Key.generateCipher(
            cipherInfo.javaCipher, cipherInfo.blockMode, dk, des2, null, false
        );

        InputStream cipherStream = new CipherInputStream(data, c);

        if (useSalt) {
            byte[] saltLine = new byte[16];
            byte[] salted = "Salted__".getBytes();
            System.arraycopy(salted, 0, saltLine, 0, salted.length);
            System.arraycopy(salt, 0, saltLine, salted.length, salt.length);
            InputStream head = new ByteArrayInputStream(saltLine);
            cipherStream = new ComboInputStream(head, cipherStream);
        }
        if (toBase64) {
            cipherStream = new Base64InputStream(cipherStream, true);
        }
        return cipherStream;
    }


    public static byte[] decrypt(String cipher, byte[] key, byte[] iv,
                                 byte[] encrypted)
        throws IOException, GeneralSecurityException {
        ByteArrayInputStream in = new ByteArrayInputStream(encrypted);
        InputStream decrypted = decrypt(cipher, key, iv, in);
        return Util.streamToBytes(decrypted);
    }

    public static InputStream decrypt(String cipher, byte[] key, byte[] iv,
                                      InputStream encrypted)
        throws IOException, GeneralSecurityException {
        CipherInfo cipherInfo = lookup(cipher);
        byte[] firstLine = Util.streamToBytes(encrypted, 16);
        if (Base64.isArrayByteBase64(firstLine)) {
            InputStream head = new ByteArrayInputStream(firstLine);
            // Need to put that 16 byte "firstLine" back into the Stream.
            encrypted = new ComboInputStream(head, encrypted);
            encrypted = new Base64InputStream(encrypted);
        } else {
            // Encrypted data wasn't base64.  Need to put the "firstLine" we
            // extracted back into the stream.
            InputStream head = new ByteArrayInputStream(firstLine);
            encrypted = new ComboInputStream(head, encrypted);
        }

        int keySize = cipherInfo.keySize;
        int ivSize = cipherInfo.ivSize;
        if (key.length == keySize / 4) // Looks like key is in hex
        {
            key = Hex.decode(key);
        }
        if (iv.length == ivSize / 4) // Looks like IV is in hex
        {
            iv = Hex.decode(iv);
        }
        DerivedKey dk = new DerivedKey(key, iv);
        Cipher c = PKCS8Key.generateCipher(cipherInfo.javaCipher,
            cipherInfo.blockMode,
            dk, cipherInfo.des2, null, true);
        return new CipherInputStream(encrypted, c);
    }

    public static byte[] encrypt(String cipher, byte[] key, byte[] iv,
                                 byte[] data)
        throws IOException, GeneralSecurityException {
        return encrypt(cipher, key, iv, data, true);
    }

    public static byte[] encrypt(String cipher, byte[] key, byte[] iv,
                                 byte[] data, boolean toBase64)
        throws IOException, GeneralSecurityException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        InputStream encrypted = encrypt(cipher, key, iv, in, toBase64);
        return Util.streamToBytes(encrypted);
    }


    public static InputStream encrypt(String cipher, byte[] key, byte[] iv,
                                      InputStream data)
        throws IOException, GeneralSecurityException {
        return encrypt(cipher, key, iv, data, true);
    }

    public static InputStream encrypt(String cipher, byte[] key, byte[] iv,
                                      InputStream data, boolean toBase64)
        throws IOException, GeneralSecurityException {
        CipherInfo cipherInfo = lookup(cipher);
        int keySize = cipherInfo.keySize;
        int ivSize = cipherInfo.ivSize;
        if (key.length == keySize / 4) {
            key = Hex.decode(key);
        }
        if (iv.length == ivSize / 4) {
            iv = Hex.decode(iv);
        }
        DerivedKey dk = new DerivedKey(key, iv);
        Cipher c = PKCS8Key.generateCipher(cipherInfo.javaCipher,
            cipherInfo.blockMode,
            dk, cipherInfo.des2, null, false);

        InputStream cipherStream = new CipherInputStream(data, c);
        if (toBase64) {
            cipherStream = new Base64InputStream(cipherStream, true);
        }
        return cipherStream;
    }


    public static DerivedKey deriveKey(char[] password, byte[] salt,
                                       int keySize, boolean des2)
        throws NoSuchAlgorithmException {
        return deriveKey(password, salt, keySize, 0, des2);
    }

    public static DerivedKey deriveKey(char[] password, byte[] salt,
                                       int keySize, int ivSize, boolean des2)
        throws NoSuchAlgorithmException {
        if (des2) {
            keySize = 128;
        }
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] pwdAsBytes = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            pwdAsBytes[i] = (byte) password[i];
        }

        md.reset();
        byte[] keyAndIv = new byte[(keySize / 8) + (ivSize / 8)];
        if (salt == null || salt.length == 0) {
            // Unsalted!  Bad idea!
            salt = null;
        }
        byte[] result;
        int currentPos = 0;
        while (currentPos < keyAndIv.length) {
            md.update(pwdAsBytes);
            if (salt != null) {
                // First 8 bytes of salt ONLY!  That wasn't obvious to me
                // when using AES encrypted private keys in "Traditional
                // SSLeay Format".
                //
                // Example:
                // DEK-Info: AES-128-CBC,8DA91D5A71988E3D4431D9C2C009F249
                //
                // Only the first 8 bytes are salt, but the whole thing is
                // re-used again later as the IV.  MUCH gnashing of teeth!
                md.update(salt, 0, 8);
            }
            result = md.digest();
            int stillNeed = keyAndIv.length - currentPos;
            // Digest gave us more than we need.  Let's truncate it.
            if (result.length > stillNeed) {
                byte[] b = new byte[stillNeed];
                System.arraycopy(result, 0, b, 0, b.length);
                result = b;
            }
            System.arraycopy(result, 0, keyAndIv, currentPos, result.length);
            currentPos += result.length;
            if (currentPos < keyAndIv.length) {
                // Next round starts with a hash of the hash.
                md.reset();
                md.update(result);
            }
        }
        if (des2) {
            keySize = 192;
            byte[] buf = new byte[keyAndIv.length + 8];
            // Make space where 3rd key needs to go (16th - 24th bytes):
            System.arraycopy(keyAndIv, 0, buf, 0, 16);
            if (ivSize > 0) {
                System.arraycopy(keyAndIv, 16, buf, 24, keyAndIv.length - 16);
            }
            keyAndIv = buf;
            // copy first 8 bytes into last 8 bytes to create 2DES key.
            System.arraycopy(keyAndIv, 0, keyAndIv, 16, 8);
        }
        if (ivSize == 0) {
            // if ivSize == 0, then "keyAndIv" array is actually all key.

            // Must be "Traditional SSLeay Format" encrypted private key in
            // PEM.  The "salt" in its entirety (not just first 8 bytes) will
            // probably be re-used later as the IV (initialization vector).
            return new DerivedKey(keyAndIv, salt);
        } else {
            byte[] key = new byte[keySize / 8];
            byte[] iv = new byte[ivSize / 8];
            System.arraycopy(keyAndIv, 0, key, 0, key.length);
            System.arraycopy(keyAndIv, key.length, iv, 0, iv.length);
            return new DerivedKey(key, iv);
        }
    }


    public static class CipherInfo {
        public final String javaCipher;
        public final String blockMode;
        public final int keySize;
        public final int ivSize;
        public final boolean des2;

        public CipherInfo(String javaCipher, String blockMode, int keySize,
                          int ivSize, boolean des2) {
            this.javaCipher = javaCipher;
            this.blockMode = blockMode;
            this.keySize = keySize;
            this.ivSize = ivSize;
            this.des2 = des2;
        }

        public String toString() {
            return javaCipher + "/" + blockMode + " " + keySize + "bit  des2=" + des2;
        }
    }

    /**
     * Converts the way OpenSSL names its ciphers into a Java-friendly naming.
     *
     * @param openSSLCipher OpenSSL cipher name, e.g. "des3" or "des-ede3-cbc".
     *                      Try "man enc" on a unix box to see what's possible.
     * @return CipherInfo object with the Java-friendly cipher information.
     */
    public static CipherInfo lookup(String openSSLCipher) {
        openSSLCipher = openSSLCipher.trim();
        if (openSSLCipher.charAt(0) == '-') {
            openSSLCipher = openSSLCipher.substring(1);
        }
        String javaCipher = openSSLCipher.toUpperCase();
        String blockMode = "CBC";
        int keySize = -1;
        int ivSize = 64;
        boolean des2 = false;


        StringTokenizer st = new StringTokenizer(openSSLCipher, "-");
        if (st.hasMoreTokens()) {
            javaCipher = st.nextToken().toUpperCase();
            if (st.hasMoreTokens()) {
                // Is this the middle token?  Or the last token?
                String tok = st.nextToken();
                if (st.hasMoreTokens()) {
                    try {
                        keySize = Integer.parseInt(tok);
                    }
                    catch (NumberFormatException nfe) {
                        // I guess 2nd token isn't an integer
                        String upper = tok.toUpperCase();
                        if (upper.startsWith("EDE3")) {
                            javaCipher = "DESede";
                        } else if (upper.startsWith("EDE")) {
                            javaCipher = "DESede";
                            des2 = true;
                        }
                    }
                    blockMode = st.nextToken().toUpperCase();
                } else {
                    try {
                        keySize = Integer.parseInt(tok);
                    }
                    catch (NumberFormatException nfe) {
                        // It's the last token, so must be mode (usually "CBC").
                        blockMode = tok.toUpperCase();
                        if (blockMode.startsWith("EDE3")) {
                            javaCipher = "DESede";
                            blockMode = "ECB";
                        } else if (blockMode.startsWith("EDE")) {
                            javaCipher = "DESede";
                            blockMode = "ECB";
                            des2 = true;
                        }
                    }
                }
            }
        }
        if (javaCipher.startsWith("BF")) {
            javaCipher = "Blowfish";
        } else if (javaCipher.startsWith("TWOFISH")) {
            javaCipher = "Twofish";
            ivSize = 128;
        } else if (javaCipher.startsWith("IDEA")) {
            javaCipher = "IDEA";
        } else if (javaCipher.startsWith("CAST6")) {
            javaCipher = "CAST6";
            ivSize = 128;
        } else if (javaCipher.startsWith("CAST")) {
            javaCipher = "CAST5";
        } else if (javaCipher.startsWith("GOST")) {
            keySize = 256;
        } else if (javaCipher.startsWith("DESX")) {
            javaCipher = "DESX";
        } else if ("DES3".equals(javaCipher)) {
            javaCipher = "DESede";
        } else if ("DES2".equals(javaCipher)) {
            javaCipher = "DESede";
            des2 = true;
        } else if (javaCipher.startsWith("RIJNDAEL")) {
            javaCipher = "Rijndael";
            ivSize = 128;
        } else if (javaCipher.startsWith("SEED")) {
            javaCipher = "SEED";
            ivSize = 128;
        } else if (javaCipher.startsWith("SERPENT")) {
            javaCipher = "Serpent";
            ivSize = 128;
        } else if (javaCipher.startsWith("Skipjack")) {
            javaCipher = "Skipjack";
            ivSize = 128;
        } else if (javaCipher.startsWith("RC6")) {
            javaCipher = "RC6";
            ivSize = 128;
        } else if (javaCipher.startsWith("TEA")) {
            javaCipher = "TEA";
        } else if (javaCipher.startsWith("XTEA")) {
            javaCipher = "XTEA";
        } else if (javaCipher.startsWith("AES")) {
            if (javaCipher.startsWith("AES128")) {
                keySize = 128;
            } else if (javaCipher.startsWith("AES192")) {
                keySize = 192;
            } else if (javaCipher.startsWith("AES256")) {
                keySize = 256;
            }
            javaCipher = "AES";
            ivSize = 128;
        } else if (javaCipher.startsWith("CAMELLIA")) {
            if (javaCipher.startsWith("CAMELLIA128")) {
                keySize = 128;
            } else if (javaCipher.startsWith("CAMELLIA192")) {
                keySize = 192;
            } else if (javaCipher.startsWith("CAMELLIA256")) {
                keySize = 256;
            }
            javaCipher = "CAMELLIA";
            ivSize = 128;
        }
        if (keySize == -1) {
            if (javaCipher.startsWith("DESede")) {
                keySize = 192;
            } else if (javaCipher.startsWith("DES")) {
                keySize = 64;
            } else {
                // RC2, RC4, RC5 and Blowfish ?
                keySize = 128;
            }
        }
        return new CipherInfo(javaCipher, blockMode, keySize, ivSize, des2);
    }


    /**
     * @param args command line arguments: [password] [cipher] [file-to-decrypt]
     *             <br>[cipher] == OpenSSL cipher name, e.g. "des3" or "des-ede3-cbc".
     *             Try "man enc" on a unix box to see what's possible.
     * @throws java.io.IOException              problems with the [file-to-decrypt]
     * @throws java.security.GeneralSecurityException decryption problems
     */
    public static void main(String[] args)
        throws IOException, GeneralSecurityException {
        if (args.length < 3) {
            System.out.println(Version.versionString());
            System.out.println("Pure-java utility to decrypt files previously encrypted by \'openssl enc\'");
            System.out.println();
            System.out.println("Usage:  java -cp commons-ssl.jar org.apache.commons.ssl.OpenSSL [args]");
            System.out.println("        [args]   == [password] [cipher] [file-to-decrypt]");
            System.out.println("        [cipher] == des, des3, des-ede3-cbc, aes256, rc2, rc4, bf, bf-cbc, etc...");
            System.out.println("                    Try 'man enc' on a unix box to see what's possible.");
            System.out.println();
            System.out.println("This utility can handle base64 or raw, salted or unsalted.");
            System.out.println();
            System.exit(1);
        }
        char[] password = args[0].toCharArray();

        InputStream in = new FileInputStream(args[2]);
        in = decrypt(args[1], password, in);

        // in = encrypt( args[ 1 ], pwdAsBytes, in, true );

        in = new BufferedInputStream(in);
        BufferedOutputStream bufOut = new BufferedOutputStream( System.out );
        Util.pipeStream(in, bufOut, false);
        bufOut.flush();
        System.out.flush();
    }

}
