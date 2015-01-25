/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Certificates.java $
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

import org.apache.kerby.util.Base64;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.lang.reflect.Method;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 19-Aug-2005
 */
public class Certificates {

    public final static CertificateFactory CF;
    public final static String LINE_ENDING = System.getProperty("line.separator");

    private final static HashMap crl_cache = new HashMap();

    public final static String CRL_EXTENSION = "2.5.29.31";
    public final static String OCSP_EXTENSION = "1.3.6.1.5.5.7.1.1";
    private final static DateFormat DF = new SimpleDateFormat("yyyy/MMM/dd");

    public interface SerializableComparator extends Comparator, Serializable {
    }

    public final static SerializableComparator COMPARE_BY_EXPIRY =
        new SerializableComparator() {
            public int compare(Object o1, Object o2) {
                X509Certificate c1 = (X509Certificate) o1;
                X509Certificate c2 = (X509Certificate) o2;
                if (c1 == c2) // this deals with case where both are null
                {
                    return 0;
                }
                if (c1 == null)  // non-null is always bigger than null
                {
                    return -1;
                }
                if (c2 == null) {
                    return 1;
                }
                if (c1.equals(c2)) {
                    return 0;
                }
                Date d1 = c1.getNotAfter();
                Date d2 = c2.getNotAfter();
                int c = d1.compareTo(d2);
                if (c == 0) {
                    String s1 = JavaImpl.getSubjectX500(c1);
                    String s2 = JavaImpl.getSubjectX500(c2);
                    c = s1.compareTo(s2);
                    if (c == 0) {
                        s1 = JavaImpl.getIssuerX500(c1);
                        s2 = JavaImpl.getIssuerX500(c2);
                        c = s1.compareTo(s2);
                        if (c == 0) {
                            BigInteger big1 = c1.getSerialNumber();
                            BigInteger big2 = c2.getSerialNumber();
                            c = big1.compareTo(big2);
                            if (c == 0) {
                                try {
                                    byte[] b1 = c1.getEncoded();
                                    byte[] b2 = c2.getEncoded();
                                    int len1 = b1.length;
                                    int len2 = b2.length;
                                    int i = 0;
                                    for (; i < len1 && i < len2; i++) {
                                        c = ((int) b1[i]) - ((int) b2[i]);
                                        if (c != 0) {
                                            break;
                                        }
                                    }
                                    if (c == 0) {
                                        c = b1.length - b2.length;
                                    }
                                }
                                catch (CertificateEncodingException cee) {
                                    // I give up.  They can be equal if they
                                    // really want to be this badly.
                                    c = 0;
                                }
                            }
                        }
                    }
                }
                return c;
            }
        };

    static {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        }
        catch (CertificateException ce) {
            ce.printStackTrace(System.out);
        }
        finally {
            CF = cf;
        }
    }

    public static String toPEMString(X509Certificate cert)
        throws CertificateEncodingException {
        return toString(cert.getEncoded());
    }

    public static String toString(byte[] x509Encoded) {
        byte[] encoded = Base64.encodeBase64(x509Encoded);
        StringBuffer buf = new StringBuffer(encoded.length + 100);
        buf.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < encoded.length; i += 64) {
            if (encoded.length - i >= 64) {
                buf.append(new String(encoded, i, 64));
            } else {
                buf.append(new String(encoded, i, encoded.length - i));
            }
            buf.append(LINE_ENDING);
        }
        buf.append("-----END CERTIFICATE-----");
        buf.append(LINE_ENDING);
        return buf.toString();
    }

    public static String toString(X509Certificate cert) {
        return toString(cert, false);
    }

    public static String toString(X509Certificate cert, boolean htmlStyle) {
        String cn = getCN(cert);
        String startStart = DF.format(cert.getNotBefore());
        String endDate = DF.format(cert.getNotAfter());
        String subject = JavaImpl.getSubjectX500(cert);
        String issuer = JavaImpl.getIssuerX500(cert);
        Iterator crls = getCRLs(cert).iterator();
        if (subject.equals(issuer)) {
            issuer = "self-signed";
        }
        StringBuffer buf = new StringBuffer(128);
        if (htmlStyle) {
            buf.append("<strong class=\"cn\">");
        }
        buf.append(cn);
        if (htmlStyle) {
            buf.append("</strong>");
        }
        buf.append(LINE_ENDING);
        buf.append("Valid: ");
        buf.append(startStart);
        buf.append(" - ");
        buf.append(endDate);
        buf.append(LINE_ENDING);
        buf.append("s: ");
        buf.append(subject);
        buf.append(LINE_ENDING);
        buf.append("i: ");
        buf.append(issuer);
        while (crls.hasNext()) {
            buf.append(LINE_ENDING);
            buf.append("CRL: ");
            buf.append((String) crls.next());
        }
        buf.append(LINE_ENDING);
        return buf.toString();
    }

    public static List getCRLs(X509Extension cert) {
        // What follows is a poor man's CRL extractor, for those lacking
        // a BouncyCastle "bcprov.jar" in their classpath.

        // It's a very basic state-machine:  look for a standard URL scheme
        // (such as http), and then start looking for a terminator.  After
        // running hexdump a few times on these things, it looks to me like
        // the UTF-8 value "65533" seems to happen near where these things
        // terminate.  (Of course this stuff is ASN.1 and not UTF-8, but
        // I happen to like some of the functions available to the String
        // object).    - juliusdavies@cucbc.com, May 10th, 2006
        byte[] bytes = cert.getExtensionValue(CRL_EXTENSION);
        LinkedList httpCRLS = new LinkedList();
        LinkedList ftpCRLS = new LinkedList();
        LinkedList otherCRLS = new LinkedList();
        if (bytes == null) {
            // just return empty list
            return httpCRLS;
        } else {
            String s;
            try {
                s = new String(bytes, "UTF-8");
            }
            catch (UnsupportedEncodingException uee) {
                // We're screwed if this thing has more than one CRL, because
                // the "indeOf( (char) 65533 )" below isn't going to work.
                s = new String(bytes);
            }
            int pos = 0;
            while (pos >= 0) {
                int x = -1, y;
                int[] indexes = new int[4];
                indexes[0] = s.indexOf("http", pos);
                indexes[1] = s.indexOf("ldap", pos);
                indexes[2] = s.indexOf("file", pos);
                indexes[3] = s.indexOf("ftp", pos);
                Arrays.sort(indexes);
                for (int i = 0; i < indexes.length; i++) {
                    if (indexes[i] >= 0) {
                        x = indexes[i];
                        break;
                    }
                }
                if (x >= 0) {
                    y = s.indexOf((char) 65533, x);
                    String crl = y > x ? s.substring(x, y - 1) : s.substring(x);
                    if (y > x && crl.endsWith("0")) {
                        crl = crl.substring(0, crl.length() - 1);
                    }
                    String crlTest = crl.trim().toLowerCase();
                    if (crlTest.startsWith("http")) {
                        httpCRLS.add(crl);
                    } else if (crlTest.startsWith("ftp")) {
                        ftpCRLS.add(crl);
                    } else {
                        otherCRLS.add(crl);
                    }
                    pos = y;
                } else {
                    pos = -1;
                }
            }
        }

        httpCRLS.addAll(ftpCRLS);
        httpCRLS.addAll(otherCRLS);
        return httpCRLS;
    }

    public static void checkCRL(X509Certificate cert)
        throws CertificateException {
        // String name = cert.getSubjectX500Principal().toString();
        byte[] bytes = cert.getExtensionValue("2.5.29.31");
        if (bytes == null) {
            // log.warn( "Cert doesn't contain X509v3 CRL Distribution Points (2.5.29.31): " + name );
        } else {
            List crlList = getCRLs(cert);
            Iterator it = crlList.iterator();
            while (it.hasNext()) {
                String url = (String) it.next();
                CRLHolder holder = (CRLHolder) crl_cache.get(url);
                if (holder == null) {
                    holder = new CRLHolder(url);
                    crl_cache.put(url, holder);
                }
                // success == false means we couldn't actually load the CRL
                // (probably due to an IOException), so let's try the next one in
                // our list.
                boolean success = holder.checkCRL(cert);
                if (success) {
                    break;
                }
            }
        }

    }

    public static BigInteger getFingerprint(X509Certificate x509)
        throws CertificateEncodingException {
        return getFingerprint(x509.getEncoded());
    }

    public static BigInteger getFingerprint(byte[] x509)
        throws CertificateEncodingException {
        MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        }
        catch (NoSuchAlgorithmException nsae) {
            throw JavaImpl.newRuntimeException(nsae);
        }

        sha1.reset();
        byte[] result = sha1.digest(x509);
        return new BigInteger(result);
    }

    private static class CRLHolder {
        private final String urlString;

        private File tempCRLFile;
        private long creationTime;
        private Set passedTest = new HashSet();
        private Set failedTest = new HashSet();

        CRLHolder(String urlString) {
            if (urlString == null) {
                throw new NullPointerException("urlString can't be null");
            }
            this.urlString = urlString;
        }

        public synchronized boolean checkCRL(X509Certificate cert)
            throws CertificateException {
            CRL crl = null;
            long now = System.currentTimeMillis();
            if (now - creationTime > 24 * 60 * 60 * 1000) {
                // Expire cache every 24 hours
                if (tempCRLFile != null && tempCRLFile.exists()) {
                    tempCRLFile.delete();
                }
                tempCRLFile = null;
                passedTest.clear();

                /*
                      Note:  if any certificate ever fails the check, we will
                      remember that fact.

                      This breaks with temporary "holds" that CRL's can issue.
                      Apparently a certificate can have a temporary "hold" on its
                      validity, but I'm not interested in supporting that.  If a "held"
                      certificate is suddenly "unheld", you're just going to need
                      to restart your JVM.
                    */
                // failedTest.clear();  <-- DO NOT UNCOMMENT!
            }

            BigInteger fingerprint = getFingerprint(cert);
            if (failedTest.contains(fingerprint)) {
                throw new CertificateException("Revoked by CRL (cached response)");
            }
            if (passedTest.contains(fingerprint)) {
                return true;
            }

            if (tempCRLFile == null) {
                try {
                    // log.info( "Trying to load CRL [" + urlString + "]" );

                    // java.net.URL blocks forever by default, so CRL-checking
                    // is freezing some systems.  Below we go to great pains
                    // to enforce timeouts for CRL-checking (5 seconds).
                    URL url = new URL(urlString);
                    URLConnection urlConn = url.openConnection();
                    if (urlConn instanceof HttpsURLConnection) {

                        // HTTPS sites will use special CRLSocket.getInstance() SocketFactory
                        // that is configured to timeout after 5 seconds:
                        HttpsURLConnection httpsConn = (HttpsURLConnection) urlConn;
                        httpsConn.setSSLSocketFactory(CRLSocket.getSecureInstance());

                    } else if (urlConn instanceof HttpURLConnection) {

                        // HTTP timeouts can only be set on Java 1.5 and up.  :-(
                        // The code required to set it for Java 1.4 and Java 1.3 is just too painful.
                        HttpURLConnection httpConn = (HttpURLConnection) urlConn;
                        try {
                            // Java 1.5 and up support these, so using reflection.  UGH!!!
                            Class c = httpConn.getClass();
                            Method setConnTimeOut = c.getDeclaredMethod("setConnectTimeout", new Class[]{Integer.TYPE});
                            Method setReadTimeout = c.getDeclaredMethod("setReadTimeout", new Class[]{Integer.TYPE});
                            setConnTimeOut.invoke(httpConn, Integer.valueOf(5000));
                            setReadTimeout.invoke(httpConn, Integer.valueOf(5000));
                        } catch (NoSuchMethodException nsme) {
                            // oh well, java 1.4 users can suffer.
                        } catch (Exception e) {
                            throw new RuntimeException("can't set timeout", e);
                        }
                    }

                    File tempFile = File.createTempFile("crl", ".tmp");
                    tempFile.deleteOnExit();

                    OutputStream out = new FileOutputStream(tempFile);
                    out = new BufferedOutputStream(out);
                    InputStream in = new BufferedInputStream(urlConn.getInputStream());
                    try {
                        Util.pipeStream(in, out);
                    }
                    catch (IOException ioe) {
                        // better luck next time
                        tempFile.delete();
                        throw ioe;
                    }
                    this.tempCRLFile = tempFile;
                    this.creationTime = System.currentTimeMillis();
                }
                catch (IOException ioe) {
                    // log.warn( "Cannot check CRL: " + e );
                }
            }

            if (tempCRLFile != null && tempCRLFile.exists()) {
                try {
                    InputStream in = new FileInputStream(tempCRLFile);
                    in = new BufferedInputStream(in);
                    synchronized (CF) {
                        crl = CF.generateCRL(in);
                    }
                    in.close();
                    if (crl.isRevoked(cert)) {
                        // log.warn( "Revoked by CRL [" + urlString + "]: " + name );
                        passedTest.remove(fingerprint);
                        failedTest.add(fingerprint);
                        throw new CertificateException("Revoked by CRL");
                    } else {
                        passedTest.add(fingerprint);
                    }
                }
                catch (IOException ioe) {
                    // couldn't load CRL that's supposed to be stored in Temp file.
                    // log.warn(  );
                }
                catch (CRLException crle) {
                    // something is wrong with the CRL
                    // log.warn(  );
                }
            }
            return crl != null;
        }
    }

    public static String getCN(X509Certificate cert) {
        String[] cns = getCNs(cert);
        boolean foundSomeCNs = cns != null && cns.length >= 1;
        return foundSomeCNs ? cns[0] : null;
    }

    public static String[] getCNs(X509Certificate cert) {
        try {
            final String subjectPrincipal = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
            final LinkedList<String> cnList = new LinkedList<String>();
            final LdapName subjectDN = new LdapName(subjectPrincipal);
            for (final Rdn rds : subjectDN.getRdns()) {
                final Attributes attributes = rds.toAttributes();
                final Attribute cn = attributes.get("cn");
                if (cn != null) {
                    try {
                        final Object value = cn.get();
                        if (value != null) {
                            cnList.add(value.toString());
                        }
                    } catch (NoSuchElementException ignore) {
                    } catch (NamingException ignore) {
                    }
                }
            }
            if (!cnList.isEmpty()) {
                return cnList.toArray(new String[cnList.size()]);
            }
        } catch (InvalidNameException ignore) {
        }
        return null;
    }

    /**
     * Extracts the array of SubjectAlt DNS names from an X509Certificate.
     * Returns null if there aren't any.
     * <p/>
     * Note:  Java doesn't appear able to extract international characters
     * from the SubjectAlts.  It can only extract international characters
     * from the CN field.
     * <p/>
     * (Or maybe the version of OpenSSL I'm using to test isn't storing the
     * international characters correctly in the SubjectAlts?).
     *
     * @param cert X509Certificate
     * @return Array of SubjectALT DNS names stored in the certificate.
     */
    public static String[] getDNSSubjectAlts(X509Certificate cert) {
        LinkedList subjectAltList = new LinkedList();
        Collection c = null;
        try {
            c = cert.getSubjectAlternativeNames();
        }
        catch (CertificateParsingException cpe) {
            // Should probably log.debug() this?
            cpe.printStackTrace();
        }
        if (c != null) {
            Iterator it = c.iterator();
            while (it.hasNext()) {
                List list = (List) it.next();
                int type = ((Integer) list.get(0)).intValue();
                // If type is 2, then we've got a dNSName
                if (type == 2) {
                    String s = (String) list.get(1);
                    subjectAltList.add(s);
                }
            }
        }
        if (!subjectAltList.isEmpty()) {
            String[] subjectAlts = new String[subjectAltList.size()];
            subjectAltList.toArray(subjectAlts);
            return subjectAlts;
        } else {
            return null;
        }
    }

    /**
     * Trims off any null entries on the array.  Returns a shrunk array.
     *
     * @param chain X509Certificate[] chain to trim
     * @return Shrunk array with all trailing null entries removed.
     */
    public static Certificate[] trimChain(Certificate[] chain) {
        for (int i = 0; i < chain.length; i++) {
            if (chain[i] == null) {
                X509Certificate[] newChain = new X509Certificate[i];
                System.arraycopy(chain, 0, newChain, 0, i);
                return newChain;
            }
        }
        return chain;
    }

    /**
     * Returns a chain of type X509Certificate[].
     *
     * @param chain Certificate[] chain to cast to X509Certificate[]
     * @return chain of type X509Certificate[].
     */
    public static X509Certificate[] x509ifyChain(Certificate[] chain) {
        if (chain instanceof X509Certificate[]) {
            return (X509Certificate[]) chain;
        } else {
            X509Certificate[] x509Chain = new X509Certificate[chain.length];
            System.arraycopy(chain, 0, x509Chain, 0, chain.length);
            return x509Chain;
        }
    }

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < args.length; i++) {
            FileInputStream in = new FileInputStream(args[i]);
            TrustMaterial tm = new TrustMaterial(in);
            Iterator it = tm.getCertificates().iterator();
            while (it.hasNext()) {
                X509Certificate x509 = (X509Certificate) it.next();
                System.out.println(toString(x509));
            }
        }
    }
}
