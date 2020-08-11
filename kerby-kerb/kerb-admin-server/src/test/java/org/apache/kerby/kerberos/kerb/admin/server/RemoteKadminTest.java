package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.commons.io.FileUtils;
import org.apache.kerby.kerberos.kerb.admin.AuthUtil;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminUtil;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServer;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.util.NetworkUtil;
import org.junit.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import java.io.File;
import java.nio.ByteBuffer;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class RemoteKadminTest {
    private static final Logger LOG = LoggerFactory.getLogger(RemoteKadminTest.class);
    
    protected static File testDir = new File(System.getProperty("test.dir", "target"));
    private static File testClassDir = new File(testDir, "test-classes");
    private static File confDir = new File(testClassDir, "conf");
    private static File workDir = new File(testDir, "work-dir");
    
    private static final String SERVER_HOST = "localhost";

    private static final String ADMIN_PRINCIPAL = "kadmin/EXAMPLE.COM@EXAMPLE.COM";
    private static final String PROTOCOL_PRINCIPAL = "adminprotocol/localhost@EXAMPLE.COM";

    private static KdcServer kdcServer;
    private static LocalKadminImpl localKadmin;
    private static AdminServer adminServer;

    private static SimpleKdcServer buildMiniKdc() throws Exception {
        KdcConfig config = new KdcConfig();
        BackendConfig backendConfig = new BackendConfig();
        backendConfig.addIniConfig(new File(confDir, "backend.conf"));
        SimpleKdcServer kdc = new SimpleKdcServer(config, backendConfig);
        kdc.setWorkDir(workDir);
        
        kdc.setKdcHost(SERVER_HOST);
        int kdcPort = NetworkUtil.getServerPort();
        kdc.setAllowTcp(true);
        kdc.setAllowUdp(false);
        kdc.setKdcTcpPort(kdcPort);
        LOG.info("Starting KDC server at " + SERVER_HOST + ":" + kdcPort);
        kdc.init();
        return kdc;
    }
    
    private static void buildLocalKadmin() throws Exception {
        localKadmin = new LocalKadminImpl(kdcServer.getKdcSetting(), kdcServer.getIdentityService());
        localKadmin.addPrincipal(PROTOCOL_PRINCIPAL);
        localKadmin.exportKeytab(new File(workDir, "protocol.keytab"), PROTOCOL_PRINCIPAL);
        localKadmin.exportKeytab(new File(workDir, "admin.keytab"), ADMIN_PRINCIPAL);
    }
    
    private static AdminServer buildAdminServer() throws Exception {
        AdminServer server = new AdminServer(confDir);
        AdminServerConfig config = server.getAdminServerConfig();
        server.setAdminHost(config.getAdminHost());
        server.setAllowTcp(true);
        server.setAllowUdp(false);
        server.setAdminServerPort(config.getAdminPort());

        server.init();
        return server;
    }

    private AdminClient buildKadminRemoteClient() throws Exception {
        final AdminConfig config = new AdminConfig();
        config.addKrb5Config(new File(confDir, "adminClient.conf"));
        AdminClient adminClient = new AdminClient(config);
        adminClient.setAdminRealm(config.getAdminRealm());
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(config.getAdminPort());

        adminClient.init();
        doSaslHandShake(adminClient, config);
        return adminClient;
    }
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        workDir.mkdirs();
        
        kdcServer = buildMiniKdc();
        kdcServer.start();

        buildLocalKadmin();
        
        adminServer = buildAdminServer();
        adminServer.start();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        adminServer.stop();
        kdcServer.stop();
        FileUtils.deleteDirectory(workDir);
    }

    @Test
    public void remoteListPrincipalTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        List<String> principals = adminClient.requestGetprincs();
        assertTrue(principals.contains("kadmin/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("adminprotocol/localhost@EXAMPLE.COM"));

        principals = adminClient.requestGetprincsWithExp("k*");
        assertTrue(principals.contains("kadmin/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        assertFalse(principals.contains("adminprotocol/localhost@EXAMPLE.COM"));
    }

    @Test
    public void remoteModifyPrincipalTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        String testPrincipal = "test/EXAMPLE.COM";
        String renamePrincipal = "test_rename/EXAMPLE.COM";
        adminClient.requestAddPrincipal(testPrincipal);
        assertTrue("Remote kadmin add principal test failed.",
                localKadmin.getPrincipals().contains(testPrincipal + "@EXAMPLE.COM"));

        adminClient.requestRenamePrincipal(testPrincipal, renamePrincipal);
        assertTrue("Remote kadmin rename principal test failed, the renamed principal does not exist.",
                localKadmin.getPrincipals().contains(renamePrincipal + "@EXAMPLE.COM"));
        assertFalse("Remote kadmin rename principal test failed, the old principal still exists.",
                localKadmin.getPrincipals().contains(testPrincipal + "@EXAMPLE.COM"));

        adminClient.requestDeletePrincipal(renamePrincipal);
        assertFalse("Remote kadmin delete principal test failed.",
                localKadmin.getPrincipals().contains(renamePrincipal + "@EXAMPLE.COM"));
    }

    @Test
    public void remoteKtaddTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        String testPrincipal = "test/EXAMPLE.COM";
        File keytabOutput = new File(testDir, "test.keytab");
        localKadmin.addPrincipal(testPrincipal);
        adminClient.requestExportKeytab(keytabOutput, testPrincipal);
        Keytab localKeytab = Keytab.loadKeytab(keytabOutput);
        List<String> principalNames = localKeytab.getPrincipals()
                .stream().map(PrincipalName::getName).collect(Collectors.toList());
        assertTrue(principalNames.contains(testPrincipal + "@EXAMPLE.COM"));
    }

    private void doSaslHandShake(AdminClient adminClient, AdminConfig config) throws Exception {
        TransportPair tpair = AdminUtil.getTransportPair(adminClient.getSetting());
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(adminClient.getSetting().getTimeout());
        KrbTransport transport = network.connect(tpair);
        Subject subject = AuthUtil.loginUsingKeytab(ADMIN_PRINCIPAL, new File(config.getKeyTabFile()));
        Subject.doAs(subject, (PrivilegedAction<Object>) () -> {
            try {
                Map<String, String> props = new HashMap<>();
                props.put(Sasl.QOP, "auth-conf");
                props.put(Sasl.SERVER_AUTH, "true");
                SaslClient saslClient = null;

                String protocol = config.getProtocol();
                String serverName = config.getServerName();
                saslClient = Sasl.createSaslClient(new String[]{"GSSAPI"}, null,
                        protocol, serverName, props, null);
                if (saslClient == null) {
                    System.out.println("Unable to find client implementation for: GSSAPI");
                    return null;
                }
                byte[] response;
                response = saslClient.hasInitialResponse()
                        ? saslClient.evaluateChallenge(new byte[0]) : new byte[0];

                sendMessage(response, saslClient, transport);

                ByteBuffer message = transport.receiveMessage();

                while (!saslClient.isComplete()) {
                    int ssComplete = message.getInt();
                    if (ssComplete == 0) {
                        System.out.println("Sasl Server completed");
                    }
                    byte[] arr = new byte[message.remaining()];
                    message.get(arr);
                    byte[] challenge = saslClient.evaluateChallenge(arr);

                    sendMessage(challenge, saslClient, transport);

                    if (!saslClient.isComplete()) {
                        message = transport.receiveMessage();
                    }
                }
            } catch (Exception e) {
                LOG.warn(e.getMessage());
            }
            return null;
        });
    }

    private void sendMessage(byte[] challenge, SaslClient saslClient, KrbTransport transport) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(challenge.length + 8);
        buffer.putInt(challenge.length + 4);
        int scComplete = saslClient.isComplete() ? 0 : 1;

        buffer.putInt(scComplete);
        buffer.put(challenge);
        buffer.flip();
        transport.sendMessage(buffer);
    }
}
