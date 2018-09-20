/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.tool.admin.local.cmd;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.server.admin.LocalHadmin;
import org.apache.kerby.util.IOUtil;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTPS certifications deploy tool.
 */
public class DeployHTTPSCertsCommand extends HadminCommand {
    private static final String USAGE
            = "\nUsage: deploy_certs [Hosts-File] [truststore_file] [truststore_password]"
            + " [Where-to-Deploy] [SSH-Port] [UserName] [Password]\n"
            + "\tExample:\n"
            + "\t\tdeploy_https hosts.txt /etc/has/truststore.jks 123456 /etc/has 22 username password\n";

    public DeployHTTPSCertsCommand(LocalHadmin hadmin) {
        super(hadmin);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        return keyGen.genKeyPair();
    }

    private static X509Certificate generateCertificate(String args, KeyPair pair)
            throws CertificateEncodingException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException {

        Date from = new Date();
        Date to = new Date(from.getTime() + 90 * 86400000L);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal(args);

        certGen.setSerialNumber(sn);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(from);
        certGen.setNotAfter(to);
        certGen.setSubjectDN(dnName);
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA1withRSA");

        return certGen.generate(pair.getPrivate());
    }

    private static File saveKeyStore(String fileName, KeyStore ks, String password)
        throws GeneralSecurityException, IOException {
        File keystoreFile = new File(fileName);
        if (keystoreFile.exists() && !keystoreFile.delete()) {
            throw new IOException("Failed to delete original file: " + fileName);
        }
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(keystoreFile);
            ks.store(out, password.toCharArray());
        } finally {
            if (out != null) {
                out.close();
            }
        }

        return keystoreFile;
    }

    private File createClientSSLConfig(String trustStorePath, String trustStorePassword,
                                       String keyStorePassword) throws HasException {
        String resourcePath = "/ssl-client.conf.template";
        try (InputStream templateResource = getClass().getResourceAsStream(resourcePath)) {
            File sslConfigFile = new File("ssl-client.conf");
            String content = IOUtil.readInput(templateResource);
            content = content.replaceAll("_location_", trustStorePath);
            content = content.replaceAll("_password_", trustStorePassword);
            content = content.replaceAll("_keyPassword_", keyStorePassword);

            IOUtil.writeFile(content, sslConfigFile);
            return sslConfigFile;
        } catch (IOException e) {
            throw new HasException("Failed to create client ssl configuration file", e);
        }
    }

    private final class KeyStoreInfo {
        KeyStore keyStore;
        String keyPasswd;

        private KeyStoreInfo(KeyStore keyStore, String keyPasswd) {
            this.keyStore = keyStore;
            this.keyPasswd = keyPasswd;
        }

        private String getKeyPasswd() {
            return this.keyPasswd;
        }

        private KeyStore getKeyStore() {
            return this.keyStore;
        }
    }

    @Override
    public void execute(String[] items) throws HasException {

        if (items.length < 7 || items.length > 8) {
            System.err.println(USAGE);
            return;
        }

        File hostFile = new File(items[1]);
        if (!hostFile.exists()) {
            throw new HasException("Host file is not exist.");
        }
        String truststoreFile = items[2];
        String truststoreSecret = items[3];
        String pathToDeploy = items[4];
        int port = Integer.valueOf(items[5]);
        String username = items[6];
        String password = "";
        if (items.length == 8) {
            password = items[7];
        }

        // Get hosts from host file
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(hostFile));
        } catch (FileNotFoundException e) {
            throw new HasException("The hosts file: " + hostFile
                + "is not exist. " + e.getMessage());
        }
        StringBuilder sb = new StringBuilder();
        String tempString;
        try {
            while ((tempString = reader.readLine()) != null) {
                sb.append(tempString);
            }
        } catch (IOException e1) {
            throw new HasException("Failed to read file. " + e1.getMessage());
        } finally {
            try {
                reader.close();
            } catch (IOException e) {
                throw new HasException(e.getMessage());
            }
        }
        String[] hostArray = sb.toString().replace(" ", "").split(",");

        // Get truststore from truststore file
        Map<String, KeyStoreInfo> keyStoreInfoMap = new HashMap<>(16);
        KeyStore trustStore;
        FileInputStream in = null;
        try {
            trustStore = KeyStore.getInstance("JKS");
            in = new FileInputStream(truststoreFile);
            trustStore.load(in, truststoreSecret.toCharArray());
        } catch (Exception e2) {
            throw new HasException("Failed to get truststore from the file: "
                + truststoreFile + ". " + e2.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    throw new HasException(e.getMessage());
                }
            }
        }
        RandomStringGenerator generator = new RandomStringGenerator.Builder()
            .withinRange('a', 'z')
            .filteredBy(CharacterPredicates.LETTERS, CharacterPredicates.DIGITS)
            .build();

        // Generate keystore map
        for (String hostname : hostArray) {
            try {
                InetAddress inetAddress = InetAddress.getLocalHost();
                String localHostname = inetAddress.getHostName();
                if (hostname.equals(localHostname)) {
                    continue;
                }
            } catch (UnknownHostException e3) {
                throw new HasException("Failed to get local hostname. " + e3.getMessage());
            }

            KeyStore ks;
            try {
                KeyPair cKP = generateKeyPair();
                String keyPassword = generator.generate(15);
                X509Certificate cert = generateCertificate("CN=" + hostname + ", O=has", cKP);
                ks = KeyStore.getInstance("JKS");
                ks.load(null, null);
                ks.setKeyEntry(hostname, cKP.getPrivate(), keyPassword.toCharArray(),
                    new Certificate[]{cert});
                KeyStoreInfo keyStoreInfo = new KeyStoreInfo(ks, keyPassword);
                keyStoreInfoMap.put(hostname, keyStoreInfo);
                trustStore.setCertificateEntry(hostname, cert);
            } catch (Exception e4) {
                throw new HasException("Failed to generate keystore. " + e4.getMessage());
            }
        }

        File finalTrustStoreFile;
        try {
            finalTrustStoreFile = saveKeyStore(truststoreFile, trustStore, password);
        } catch (Exception e5) {
            throw new HasException("Failed to generate trust store files. " + e5.getMessage());
        }

        // Generate keystore, truststore, ssl config files and transfer them to destination
        for (String hostname : hostArray) {
            List<File> files = new ArrayList<>(3);
            try {
                KeyStoreInfo keyStoreInfo = keyStoreInfoMap.get(hostname);
                File file = saveKeyStore(hostname + "_keystore.jks",
                    keyStoreInfo.getKeyStore(), keyStoreInfo.getKeyPasswd());
                files.add(file);
                files.add(finalTrustStoreFile);
                files.add(createClientSSLConfig(pathToDeploy + "/truststore.jks",
                    truststoreSecret, keyStoreInfo.getKeyPasswd()));
            } catch (Exception e6) {
                throw new HasException("Failed to generate key store files. " + e6.getMessage());
            }

            JSch jsch = new JSch();
            Session session;
            try {
                session = jsch.getSession(username, hostname, port);
            } catch (JSchException e7) {
                throw new HasException(e7.getMessage());
            }
            session.setPassword(password);

            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            ChannelSftp channel;
            try {
                session.connect();
                channel = (ChannelSftp) session.openChannel("sftp");
                channel.connect();
            } catch (JSchException e8) {
                throw new HasException("Failed to set the session: " + e8.getMessage());
            }
            try {
                String path = "";
                String[] paths = pathToDeploy.split("/");
                for (int i = 1; i < paths.length; i++) {
                    path = path + "/" + paths[i];
                    try {
                        channel.cd(path);
                    } catch (SftpException e9) {
                        if (e9.id == ChannelSftp.SSH_FX_NO_SUCH_FILE) {
                            channel.mkdir(path);
                        } else {
                            throw new HasException(e9.getMessage());
                        }
                    }
                }
            } catch (SftpException e10) {
                throw new HasException("Failed to mkdir path: " + e10.getMessage());
            }

            for (File file : files) {
                try {
                    channel.put(file.getAbsolutePath(), file.getName());
                } catch (SftpException e11) {
                    throw new HasException("Failed to send the https cert files. "
                        + e11.getMessage());
                }
            }
            channel.disconnect();
        }
    }
}
