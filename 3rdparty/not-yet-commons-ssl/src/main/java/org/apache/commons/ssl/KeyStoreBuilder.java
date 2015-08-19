/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/KeyStoreBuilder.java $
 * $Revision: 180 $
 * $Date: 2014-09-23 11:33:47 -0700 (Tue, 23 Sep 2014) $
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

import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1Sequence;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Builds Java Key Store files out of pkcs12 files, or out of pkcs8 files +
 * certificate chains.  Also supports OpenSSL style private keys (encrypted or
 * unencrypted).
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 4-Nov-2006
 */
public class KeyStoreBuilder {
    private final static String PKCS7_ENCRYPTED = "1.2.840.113549.1.7.6";

    public static KeyStore build(byte[] jksOrCerts, char[] password)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {
        return build(jksOrCerts, null, password);
    }

    public static KeyStore build(byte[] jksOrCerts, byte[] privateKey,
                                 char[] password)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {
        return build(jksOrCerts, privateKey, password, null);
    }


    public static KeyStore build(byte[] jksOrCerts, byte[] privateKey,
                                 char[] jksPassword, char[] keyPassword)
        throws IOException, CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, ProbablyBadPasswordException,
        UnrecoverableKeyException {

        if (keyPassword == null || keyPassword.length <= 0) {
            keyPassword = jksPassword;
        }

        BuildResult br1 = parse(jksOrCerts, jksPassword, keyPassword);
        BuildResult br2 = null;
        KeyStore jks = null;
        if (br1.jks != null) {
            jks = br1.jks;
        } else if (privateKey != null && privateKey.length > 0) {
            br2 = parse(privateKey, jksPassword, keyPassword);
            if (br2.jks != null) {
                jks = br2.jks;
            }
        }

        // If we happened to find a JKS file, let's just return that.
        // JKS files get priority (in case some weirdo specifies both a PKCS12
        // and a JKS file!).
        if (jks != null) {
            // Make sure the keystore we found is not corrupt.
            br1 = validate(jks, keyPassword);
            if (br1 == null) {
                return jks;
            }
        }

        List keys = br1.keys;
        List chains = br1.chains;        
        boolean atLeastOneNotSet = keys == null || chains == null || keys.isEmpty() || chains.isEmpty();
        if (atLeastOneNotSet && br2 != null) {
            if (br2.keys != null && !br2.keys.isEmpty()) {
                // Notice that the key from build-result-2 gets priority over the
                // key from build-result-1 (if both had valid keys).
                keys = br2.keys;
            }
            if (chains == null || chains.isEmpty()) {
                chains = br2.chains;
            }
        }

        atLeastOneNotSet = keys == null || chains == null || keys.isEmpty() || chains.isEmpty();
        if (atLeastOneNotSet) {
            String missing = "";
            if (keys == null) {
                missing = " [Private key missing (bad password?)]";
            }
            if (chains == null) {
                missing += " [Certificate chain missing]";
            }
            throw new KeyStoreException("Can't build keystore:" + missing);
        } else {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, jksPassword);
            Iterator keysIt = keys.iterator();
            Iterator chainsIt = chains.iterator();
            int i = 1;
            while (keysIt.hasNext() && chainsIt.hasNext()) {
                Key key = (Key) keysIt.next();
                Certificate[] c = (Certificate[]) chainsIt.next();
                X509Certificate theOne = buildChain(key, c);
                String alias = "alias_" + i++;
                // The theOne is not null, then our chain was probably altered.
                // Need to trim out the newly introduced null entries at the end of
                // our chain.
                if (theOne != null) {
                    c = Certificates.trimChain(c);
                    alias = Certificates.getCN(theOne);
                    alias = alias.replace(' ', '_');
                }
                ks.setKeyEntry(alias, key, keyPassword, c);
            }
            return ks;
        }
    }

    /**
     * Builds the chain up such that chain[ 0 ] contains the public key
     * corresponding to the supplied private key.
     *
     * @param key   private key
     * @param chain array of certificates to build chain from
     * @return theOne!
     * @throws java.security.KeyStoreException        no certificates correspond to private key
     * @throws java.security.cert.CertificateException     java libraries complaining
     * @throws java.security.NoSuchAlgorithmException java libraries complaining
     * @throws java.security.InvalidKeyException      java libraries complaining
     * @throws java.security.NoSuchProviderException  java libraries complaining
     */
    public static X509Certificate buildChain(Key key, Certificate[] chain)
        throws CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException {
        X509Certificate theOne = null;
        if (key instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
            BigInteger publicExponent = rsa.getPublicExponent();
            BigInteger modulus = rsa.getModulus();
            for (int i = 0; i < chain.length; i++) {
                X509Certificate c = (X509Certificate) chain[i];
                PublicKey pub = c.getPublicKey();
                if (pub instanceof RSAPublicKey) {
                    RSAPublicKey certKey = (RSAPublicKey) pub;
                    BigInteger pe = certKey.getPublicExponent();
                    BigInteger mod = certKey.getModulus();
                    if (publicExponent.equals(pe) && modulus.equals(mod)) {
                        theOne = c;
                    }
                }
            }
            if (theOne == null) {
                throw new KeyStoreException("Can't build keystore: [No certificates belong to the private-key]");
            }
            X509Certificate[] newChain;
            newChain = X509CertificateChainBuilder.buildPath(theOne, chain);
            Arrays.fill(chain, null);
            System.arraycopy(newChain, 0, chain, 0, newChain.length);
        }
        return theOne;
    }

    public static BuildResult validate(KeyStore jks, char[] keyPass)
        throws CertificateException, KeyStoreException,
        NoSuchAlgorithmException, InvalidKeyException,
        NoSuchProviderException, UnrecoverableKeyException {
        Enumeration en = jks.aliases();
        boolean atLeastOneSuccess = false;
        boolean atLeastOneFailure = false;

        List keys = new LinkedList();
        List chains = new LinkedList();
        while (en.hasMoreElements()) {
            String alias = (String) en.nextElement();
            if (jks.isKeyEntry(alias)) {
                try {
                    PrivateKey key = (PrivateKey) jks.getKey(alias, keyPass);
                    // No Exception thrown, so we're good!
                    atLeastOneSuccess = true;
                    Certificate[] chain = jks.getCertificateChain(alias);
                    X509Certificate[] c;
                    if (chain != null) {
                        c = Certificates.x509ifyChain(chain);
                        X509Certificate theOne = buildChain(key, c);
                        // The theOne is not null, then our chain was probably
                        // altered.  Need to trim out the newly introduced null
                        // entries at the end of our chain.
                        if (theOne != null) {
                            c = (X509Certificate[]) Certificates.trimChain(c);
                            jks.deleteEntry(alias);
                            jks.setKeyEntry(alias, key, keyPass, c);
                        }
                        keys.add(key);
                        chains.add(c);
                    }
                } catch (GeneralSecurityException gse) {
                    atLeastOneFailure = true;
                    // This is not the key you're looking for.
                }
            }
        }
        if (!atLeastOneSuccess) {
            throw new KeyStoreException("No private keys found in keystore!");
        }
        // The idea is a bit hacky:  if we return null, all is cool.  If
        // we return a list, we're telling upstairs to abandon the JKS and
        // build a new one from the BuildResults we provide.
        // (Sun's builtin SSL refuses to deal with keystores where not all
        // keys can be decrypted).
        return atLeastOneFailure ? new BuildResult(keys, chains, null) : null;
    }

    public static class BuildResult {
        protected final List keys;
        protected final List chains;
        protected final KeyStore jks;

        protected BuildResult(List keys, List chains, KeyStore jks) {
            if (keys == null || keys.isEmpty()) {
                this.keys = null;
            } else {
                this.keys = Collections.unmodifiableList(keys);
            }
            this.jks = jks;
            List x509Chains = new LinkedList();
            if (chains != null) {
                Iterator it = chains.iterator();
                while (it.hasNext()) {
                    Certificate[] chain = (Certificate[]) it.next();
                    if (chain != null && chain.length > 0) {
                        int len = chain.length;
                        X509Certificate[] x509 = new X509Certificate[len];
                        for (int i = 0; i < x509.length; i++) {
                            x509[i] = (X509Certificate) chain[i];
                        }
                        x509Chains.add(x509);
                    }
                }
            }
            if (x509Chains == null || x509Chains.isEmpty()) {
                this.chains = null;
            } else {
                this.chains = Collections.unmodifiableList(x509Chains);
            }
        }
    }


    public static BuildResult parse(byte[] stuff, char[] jksPass,
                                    char[] keyPass)
            throws IOException, CertificateException, KeyStoreException,
            ProbablyBadPasswordException {

        return parse(stuff, jksPass, keyPass, false);
    }

    static BuildResult parse(byte[] stuff, char[] jksPass,
                             char[] keyPass, boolean forTrustMaterial)
        throws IOException, CertificateException, KeyStoreException,
        ProbablyBadPasswordException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Key key = null;
        Certificate[] chain = null;
        try {
            PKCS8Key pkcs8Key = new PKCS8Key(stuff, jksPass);
            key = pkcs8Key.getPrivateKey();
        }
        catch (ProbablyBadPasswordException pbpe) {
            throw pbpe;
        }
        catch (GeneralSecurityException gse) {
            // no luck
        }

        List pemItems = PEMUtil.decode(stuff);
        Iterator it = pemItems.iterator();
        LinkedList certificates = new LinkedList();
        while (it.hasNext()) {
            PEMItem item = (PEMItem) it.next();
            byte[] derBytes = item.getDerBytes();
            String type = item.pemType.trim().toUpperCase();
            if (type.startsWith("CERT") ||
                type.startsWith("X509") ||
                type.startsWith("PKCS7")) {
                ByteArrayInputStream in = new ByteArrayInputStream(derBytes);
                X509Certificate c = (X509Certificate) cf.generateCertificate(in);
                certificates.add(c);
            }
            chain = toChain(certificates);
        }

        if (chain != null || key != null) {
            List chains = chain != null ? Collections.singletonList(chain) : null;
            List keys = key != null ? Collections.singletonList(key) : null;
            return new BuildResult(keys, chains, null);
        }

        boolean isProbablyPKCS12 = false;
        boolean isASN = false;
        Asn1PkcsStructure asn1 = null;
        try {
            asn1 = Asn1PkcsUtil.analyze(stuff);
            isASN = true;
            isProbablyPKCS12 = asn1.oids.contains(PKCS7_ENCRYPTED);
            if (!isProbablyPKCS12 && asn1.bigPayload != null) {
                asn1 = Asn1PkcsUtil.analyze(asn1.bigPayload);
                isProbablyPKCS12 = asn1.oids.contains(PKCS7_ENCRYPTED);
            }
        }
        catch (Exception e) {
            // isProbablyPKCS12 and isASN are set properly by now.
        }

        ByteArrayInputStream stuffStream = new ByteArrayInputStream(stuff);
        // Try default keystore... then try others.
        BuildResult br = tryJKS(KeyStore.getDefaultType(), stuffStream, jksPass, keyPass, forTrustMaterial);
        if (br == null) {
            br = tryJKS("jks", stuffStream, jksPass, keyPass, forTrustMaterial);
            if (br == null) {
                br = tryJKS("jceks", stuffStream, jksPass, keyPass, forTrustMaterial);
                if (br == null) {
                    br = tryJKS("BKS", stuffStream, jksPass, keyPass, forTrustMaterial);
                    if (br == null) {
                        br = tryJKS("UBER", stuffStream, jksPass, keyPass, forTrustMaterial);
                    }
                }
            }
        }
        if (br != null) {
            return br;
        }
        if (isASN && isProbablyPKCS12) {
            br = tryJKS("pkcs12", stuffStream, jksPass, null, forTrustMaterial);
        }

        if (br == null) {
            // Okay, it's ASN.1, but it's not PKCS12.  Only one possible
            // interesting things remains:  X.509.
            stuffStream.reset();

            try {
                certificates = new LinkedList();
                Collection certs = cf.generateCertificates(stuffStream);
                it = certs.iterator();
                while (it.hasNext()) {
                    X509Certificate x509 = (X509Certificate) it.next();
                    certificates.add(x509);
                }
                chain = toChain(certificates);
                if (chain != null && chain.length > 0) {
                    List chains = Collections.singletonList(chain);
                    return new BuildResult(null, chains, null);
                }
            }
            catch (CertificateException ce) {
                // oh well
            }

            stuffStream.reset();
            // Okay, still no luck.  Maybe it's an ASN.1 DER stream
            // containing only a single certificate?  (I don't completely
            // trust CertificateFactory.generateCertificates).
            try {
                Certificate c = cf.generateCertificate(stuffStream);
                X509Certificate x509 = (X509Certificate) c;
                chain = toChain(Collections.singleton(x509));
                if (chain != null && chain.length > 0) {
                    List chains = Collections.singletonList(chain);
                    return new BuildResult(null, chains, null);
                }
            }
            catch (CertificateException ce) {
                // oh well
            }
        }

        br = tryJKS("pkcs12", stuffStream, jksPass, null, forTrustMaterial);
        if (br != null) {
            // no exception thrown, so must be PKCS12.
            /*
            Hmm, well someone finally reported this bug!   And they want the library to be quiet....
            Commenting out for now, maybe investigate why it's happening one day....

            System.out.println("Please report bug!");
            System.out.println("PKCS12 detection failed to realize this was PKCS12!");
            System.out.println(asn1);
            */
            return br;
        }
        throw new KeyStoreException("failed to extract any certificates or private keys - maybe bad password?");
    }

    private static BuildResult tryJKS(
            String keystoreType, ByteArrayInputStream in, char[] jksPassword, char[] keyPassword,
            boolean forTrustMaterial
    ) throws ProbablyBadPasswordException {
        in.reset();
        if (keyPassword == null || keyPassword.length <= 0) {
            keyPassword = jksPassword;
        }

        keystoreType = keystoreType.trim().toLowerCase();
        boolean isPKCS12 = "pkcs12".equalsIgnoreCase(keystoreType);
        try {
            Key key = null;
            Certificate[] chain = null;
            UnrecoverableKeyException uke = null;
            KeyStore jksKeyStore = KeyStore.getInstance(keystoreType);
            jksKeyStore.load(in, jksPassword);
            Enumeration en = jksKeyStore.aliases();
            while (en.hasMoreElements()) {
                String alias = (String) en.nextElement();
                if (jksKeyStore.isKeyEntry(alias)) {
                    try {
                        if (keyPassword != null) {
                            key = jksKeyStore.getKey(alias, keyPassword);
                        }
                        if (key instanceof PrivateKey) {
                            chain = jksKeyStore.getCertificateChain(alias);
                            break;
                        }
                    } catch (UnrecoverableKeyException e) {
                        uke = e;  // We might throw this one later. 
                    } catch (GeneralSecurityException gse) {
                        // Swallow... keep looping.
                    }
                }
                if (isPKCS12 && en.hasMoreElements()) {
                    System.out.println("what kind of weird pkcs12 file has more than one alias?");
                }
            }
            if (key == null && uke != null) {
                // If we're trying to load KeyMaterial, then we *need* that key we spotted.
                // But if we're trying to load TrustMaterial, then we're fine, and we can ignore the key.
                if (!forTrustMaterial) {
                    throw new ProbablyBadPasswordException("Probably bad JKS-Key password: " + uke);
                }
            }
            if (isPKCS12) {
                // PKCS12 is supposed to be just a key and a chain, anyway.
                jksKeyStore = null;
            }

            List keys = Collections.singletonList(key);
            List chains = Collections.singletonList(chain);
            return new BuildResult(keys, chains, jksKeyStore);
        }
        catch (ProbablyBadPasswordException pbpe) {
            throw pbpe;
        }
        catch (GeneralSecurityException gse) {
            // swallow it, return null
            return null;
        }
        catch (IOException ioe) {
            String msg = ioe.getMessage();
            msg = msg != null ? msg.trim().toLowerCase() : "";
            if (isPKCS12) {
                int x = msg.indexOf("failed to decrypt");
                int y = msg.indexOf("verify mac");
                x = Math.max(x, y);
                if (x >= 0) {
                    throw new ProbablyBadPasswordException("Probably bad PKCS12 password: " + ioe);
                }
            } else {
                int x = msg.indexOf("password");
                if (x >= 0) {
                    throw new ProbablyBadPasswordException("Probably bad JKS password: " + ioe);
                }
            }
            // swallow it, return null.
            return null;
        }
    }

    private static X509Certificate[] toChain(Collection certs) {
        if (certs != null && !certs.isEmpty()) {
            X509Certificate[] x509Chain = new X509Certificate[certs.size()];
            certs.toArray(x509Chain);
            return x509Chain;
        } else {
            return null;
        }
    }


    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("KeyStoreBuilder:  creates '[alias].jks' (Java Key Store)");
            System.out.println("    -topk8 mode:  creates '[alias].pem' (x509 chain + unencrypted pkcs8)");
            System.out.println("[alias] will be set to the first CN value of the X509 certificate.");
            System.out.println("-------------------------------------------------------------------");
            System.out.println("Usage1: [password] [file:pkcs12]");
            System.out.println("Usage2: [password] [file:private-key] [file:certificate-chain]");
            System.out.println("Usage3: -topk8 [password] [file:jks]");
            System.out.println("-------------------------------------------------------------------");
            System.out.println("[private-key] can be openssl format, or pkcs8.");
            System.out.println("[password] decrypts [private-key], and also encrypts outputted JKS file.");
            System.out.println("All files can be PEM or DER.");
            System.exit(1);
        }
        char[] password = args[0].toCharArray();
        boolean toPKCS8 = false;
        if ("-topk8".equalsIgnoreCase(args[0])) {
            toPKCS8 = true;
            password = args[1].toCharArray();
            args[1] = args[2];
            args[2] = null;
        }

        FileInputStream fin1 = new FileInputStream(args[1]);
        byte[] bytes1 = Util.streamToBytes(fin1);
        byte[] bytes2 = null;
        if (args.length > 2 && args[2] != null) {
            FileInputStream fin2 = new FileInputStream(args[2]);
            bytes2 = Util.streamToBytes(fin2);
        }

        KeyStore ks = build(bytes1, bytes2, password);
        Enumeration en = ks.aliases();
        String alias = "keystorebuilder";

        // We're going to assume that the biggest key is the one we want
        // to convert to PKCS8 (PEM).  That's until someone figures out a
        // better way to deal with this annoying situation (more than 1
        // key in the KeyStore).
        int biggestKey = 0;
        while (en.hasMoreElements()) {
            String s = (String) en.nextElement();
            try {
                PrivateKey pk = (PrivateKey) ks.getKey(s, password);
                byte[] encoded = pk.getEncoded();
                int len = encoded != null ? encoded.length : 0;
                if (len >= biggestKey) {
                    biggestKey = len;
                    alias = s;
                }
            } catch (Exception e) {
                // oh well, try next one.
            }
        }

        String suffix = toPKCS8 ? ".pem" : ".jks";
        String fileName = alias;
        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain != null && chain[0] != null) {
            String cn = Certificates.getCN((X509Certificate) chain[0]);
            cn = cn != null ? cn.trim() : "";
            if (!"".equals(cn)) {
                fileName = cn;
            }
        }

        File f = new File(fileName + suffix);
        int count = 1;
        while (f.exists()) {
            f = new File(alias + "_" + count + suffix);
            count++;
        }

        FileOutputStream fout = new FileOutputStream(f);
        if (toPKCS8) {
            List pemItems = new LinkedList();
            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            chain = ks.getCertificateChain(alias);
            byte[] pkcs8DerBytes = null;
            if (key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) key;
                Asn1Sequence seq = new Asn1Sequence();
                seq.addItem(new Asn1Integer(BigInteger.ZERO));
                seq.addItem(new Asn1Integer(rsa.getModulus()));
                seq.addItem(new Asn1Integer(rsa.getPublicExponent()));
                seq.addItem(new Asn1Integer(rsa.getPrivateExponent()));
                seq.addItem(new Asn1Integer(rsa.getPrimeP()));
                seq.addItem(new Asn1Integer(rsa.getPrimeQ()));
                seq.addItem(new Asn1Integer(rsa.getPrimeExponentP()));
                seq.addItem(new Asn1Integer(rsa.getPrimeExponentQ()));
                seq.addItem(new Asn1Integer(rsa.getCrtCoefficient()));
                byte[] derBytes = seq.encode();
                PKCS8Key pkcs8 = new PKCS8Key(derBytes, null);
                pkcs8DerBytes = pkcs8.getDecryptedBytes();
            } else if (key instanceof DSAPrivateKey) {
                DSAPrivateKey dsa = (DSAPrivateKey) key;
                DSAParams params = dsa.getParams();
                BigInteger g = params.getG();
                BigInteger p = params.getP();
                BigInteger q = params.getQ();
                BigInteger x = dsa.getX();
                BigInteger y = q.modPow(x, p);

                Asn1Sequence seq = new Asn1Sequence();
                seq.addItem(new Asn1Integer(BigInteger.ZERO));
                seq.addItem(new Asn1Integer(p));
                seq.addItem(new Asn1Integer(q));
                seq.addItem(new Asn1Integer(g));
                seq.addItem(new Asn1Integer(y));
                seq.addItem(new Asn1Integer(x));
                byte[] derBytes = seq.encode();
                PKCS8Key pkcs8 = new PKCS8Key(derBytes, null);
                pkcs8DerBytes = pkcs8.getDecryptedBytes();
            }
            if (chain != null && chain.length > 0) {
                for (int i = 0; i < chain.length; i++) {
                    X509Certificate x509 = (X509Certificate) chain[i];
                    byte[] derBytes = x509.getEncoded();
                    PEMItem item = new PEMItem(derBytes, "CERTIFICATE");
                    pemItems.add(item);
                }
            }
            if (pkcs8DerBytes != null) {
                PEMItem item = new PEMItem(pkcs8DerBytes, "PRIVATE KEY");
                pemItems.add(item);
            }
            byte[] pem = PEMUtil.encode(pemItems);
            fout.write(pem);
        } else {
            // If we're not converting to unencrypted PKCS8 style PEM,
            // then we are converting to Sun JKS.  It happens right here:
            KeyStore jks = KeyStore.getInstance(KeyStore.getDefaultType());
            jks.load(null, password);
            jks.setKeyEntry(alias, ks.getKey(alias, password), password, ks.getCertificateChain(alias));
            jks.store(fout, password);
        }
        fout.flush();
        fout.close();
        System.out.println("Successfuly wrote: [" + f.getPath() + "]");
    }


}
