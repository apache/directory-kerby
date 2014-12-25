package org.apache.kerberos.kerb.server;

import org.apache.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerberos.kerb.keytab.Keytab;
import org.apache.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.KerberosTime;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.PrincipalName;

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

    public TestKdcServer() {
        this(createConf());
    }

    public TestKdcServer(Properties conf) {
        super();
        getConfig().getConf().addPropertiesConfig(conf);
    }

    @Override
    public void init() {
        super.init();

        createPrincipals("krbtgt");
    }

    public String getKdcRealm() {
        return getConfig().getKdcRealm();
    }

    public synchronized void createPrincipal(String principal, String password) {
        KrbIdentity identity = new KrbIdentity(principal);
        List<EncryptionType> encTypes = getConfig().getEncryptionTypes();
        List<EncryptionKey> encKeys = null;
        try {
            encKeys = EncryptionUtil.generateKeys(fixPrincipal(principal), password, encTypes);
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
            createPrincipal(fixPrincipal(principal), passwd);
        }
    }

    private String fixPrincipal(String principal) {
        if (! principal.contains("@")) {
            principal += "@" + getKdcRealm();
        }
        return principal;
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