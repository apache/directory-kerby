package org.haox.kerb.server;

import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.keytab.Keytab;
import org.haox.kerb.keytab.KeytabEntry;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

public class TestKdcServer extends SimpleKdcServer {

    public static final String ORG_DOMAIN = KdcConfigKey.KDC_DOMAIN.getPropertyKey();
    public static final String KDC_REALM = KdcConfigKey.KDC_REALM.getPropertyKey();
    public static final String KDC_HOST = KdcConfigKey.KDC_HOST.getPropertyKey();
    public static final String KDC_PORT = KdcConfigKey.KDC_PORT.getPropertyKey();
    public static final String WORK_DIR = KdcConfigKey.WORK_DIR.getPropertyKey();

    private static final Properties DEFAULT_CONFIG = new Properties();
    static {
        DEFAULT_CONFIG.setProperty(KDC_HOST, "localhost");
        DEFAULT_CONFIG.setProperty(KDC_PORT, "8018");
        DEFAULT_CONFIG.setProperty(ORG_DOMAIN, "test.com");
        DEFAULT_CONFIG.setProperty(KDC_REALM, "TEST.COM");
    }

    public static Properties createConf() {
        return (Properties) DEFAULT_CONFIG.clone();
    }

    private File workDir;

    public TestKdcServer() {
        this(createConf());
    }

    public TestKdcServer(Properties conf) {
        getConfig().getConf().addPropertiesConfig(conf);

        this.workDir = new File(workDir, Long.toString(System.currentTimeMillis()));
        if (! workDir.exists() && ! workDir.mkdirs()) {
            throw new RuntimeException("Cannot create directory " + workDir);
        }
    }

    public synchronized void createPrincipal(String principal, String password) {
        KrbIdentity identity = new KrbIdentity(principal);
        List<EncryptionType> encTypes = getConfig().getEncryptionTypes();
        List<EncryptionKey> encKeys = null;
        try {
            encKeys = EncryptionUtil.generateKeys(principal, password, encTypes);
        } catch (KrbException e) {
            throw new RuntimeException("Failed to generate encryption keys", e);
        }
        identity.addKeys(encKeys);
        getIdentityService().addIdentity(identity);
    }

    public void createPrincipals(String ... principals) {
        String passwd;
        for (String principal : principals) {
            passwd = UUID.randomUUID().toString();
            createPrincipal(principal, passwd);
        }
    }

    public void exportPrincipals(File keytabFile) throws IOException {
        Keytab keytab = new Keytab();

        List<KrbIdentity> identities = getIdentityService().getIdentities();
        for (KrbIdentity identity : identities) {
            PrincipalName principal = identity.getPrincipal();
            KerberosTime timestamp = new KerberosTime();
            for (EncryptionType encType : identity.getKeys().keySet()) {
                EncryptionKey ekey = identity.getKeys().get(encType);
                int keyVersion = ekey.getKvno();
                keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
            }
        }

        keytab.store(keytabFile);
    }
}