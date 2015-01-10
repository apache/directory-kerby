package org.apache.commons.httpclient.contrib.ssl;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

import java.io.File;
import java.net.URL;

public class TestHttpclientContrib {

    @Test
    public void theTest() throws Exception {
        registerCerts();
    }

    public static void registerCerts() throws Exception {
        File keyFile = new File("samples/keystores/Sun.jks.ks");
        File trustFile = new File("samples/cacerts-with-78-entries.jks");
        URL ks = keyFile.toURI().toURL();
        URL ts = trustFile.toURI().toURL();

        AuthSSLProtocolSocketFactory sf;
        sf = new AuthSSLProtocolSocketFactory(ks, "changeit", ts, "changeit");
        sf.setCheckHostname(false);

        // There should be 78 certs in this trust-chain.
        assertEquals(78, sf.getTrustChain().getCertificates().size());

        TrustSSLProtocolSocketFactory tf;
        tf = new TrustSSLProtocolSocketFactory(trustFile.getAbsolutePath(), "changeit".toCharArray());
        tf.setCheckHostname(false);

        String scheme1 = "https-test1";
        Protocol.registerProtocol(scheme1, new Protocol(scheme1, (ProtocolSocketFactory) sf, 443));
        String scheme2 = "https-test2";
        Protocol.registerProtocol(scheme2, new Protocol(scheme2, (ProtocolSocketFactory) tf, 443));
    }

}
