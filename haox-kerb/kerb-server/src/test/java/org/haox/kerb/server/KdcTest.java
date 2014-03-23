package org.haox.kerb.server;

import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.kerberos.client.TgTicket;
import org.apache.directory.shared.kerberos.KerberosUtils;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.apache.directory.shared.kerberos.codec.types.EncryptionType.*;

public class KdcTest {
    private static Set<EncryptionType> DEFAULT_ENCRYPTION_TYPES;

    static
    {
        DEFAULT_ENCRYPTION_TYPES = new HashSet<EncryptionType>();

        DEFAULT_ENCRYPTION_TYPES.add( AES128_CTS_HMAC_SHA1_96 );
        DEFAULT_ENCRYPTION_TYPES.add( AES256_CTS_HMAC_SHA1_96 );
        DEFAULT_ENCRYPTION_TYPES.add( DES_CBC_MD5 );
        DEFAULT_ENCRYPTION_TYPES.add( DES3_CBC_SHA1_KD );
        DEFAULT_ENCRYPTION_TYPES.add( RC4_HMAC );
        //DEFAULT_ENCRYPTION_TYPES.add( RC4_HMAC_EXP );

        DEFAULT_ENCRYPTION_TYPES = KerberosUtils.orderEtypesByStrength(DEFAULT_ENCRYPTION_TYPES);
    }
    private String clientPrincipal = "drankye@EXAMPLE.COM";
    private String password = "123456";
    private String hostname = "localhost";
    private int port = 8088;

    private KdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new KdcServer(port);
        kdcServer.start();
    }

    @Test
    public void testKdc() throws Exception {
        KdcConfig config = KdcConfig.getDefaultConfig();
        config.setUseUdp(false);
        config.setHostName(hostname);
        config.setKdcPort(port);
        config.setTimeout(1000);
        config.setEncryptionTypes(DEFAULT_ENCRYPTION_TYPES);

        KdcConnection con = new KdcConnection(config);
        TgTicket tgt = con.getTgt(clientPrincipal, password);
        Assert.assertNotNull(tgt);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}