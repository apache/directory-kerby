package org.haox.kerb.server;

import org.apache.commons.io.FileUtils;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.haox.kerb.server.identity.Identity;
import org.haox.kerb.server.identity.KrbIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.text.MessageFormat;
import java.util.*;

public class TestKdcServer extends SimpleKdcServer {
    private static final Logger logger = LoggerFactory.getLogger(TestKdcServer.class);

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
    private File krb5conf;

    public TestKdcServer(Properties conf) throws Exception {
        getConfig().getConf().addPropertiesConfig(conf);

        this.workDir = new File(workDir, Long.toString(System.currentTimeMillis()));
        if (! workDir.exists()
                && ! workDir.mkdirs()) {
            throw new RuntimeException("Cannot create directory " + workDir);
        }
        logger.info("ConfigImpl:");
        logger.info("---------------------------------------------------------------");
        for (Map.Entry entry : conf.entrySet()) {
            logger.info("  {}: {}", entry.getKey(), entry.getValue());
        }
        logger.info("---------------------------------------------------------------");
    }

    public File getKrb5conf() {
        return krb5conf;
    }

    @Override
    protected void initConfig() {
        super.initConfig();

        try {
            StringBuilder sb = new StringBuilder();
            InputStream is = getClass().getResourceAsStream("minikdc-krb5.conf");
            BufferedReader r = new BufferedReader(new InputStreamReader(is));
            String line = r.readLine();
            while (line != null) {
                sb.append(line).append("{3}");
                line = r.readLine();
            }
            r.close();
            krb5conf = new File(workDir, "krb5.conf").getAbsoluteFile();
            FileUtils.writeStringToFile(krb5conf,
                    MessageFormat.format(sb.toString(), getKdcRealm(), getKdcHost(),
                            Integer.toString(getKdcPort()), System.getProperty("line.separator")));
            System.setProperty("java.security.krb5.conf", krb5conf.getAbsolutePath());

            System.setProperty("sun.security.krb5.debug", String.valueOf(enableDebug()));

            // refresh the org.haox.config
            Class<?> classRef;
            if (System.getProperty("java.vendor").contains("IBM")) {
                classRef = Class.forName("com.ibm.security.krb5.internal.ConfigImpl");
            } else {
                classRef = Class.forName("sun.security.krb5.ConfigImpl");
            }
            Method refreshMethod = classRef.getMethod("refresh", new Class[0]);
            refreshMethod.invoke(classRef, new Object[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.info("TestKdcServer setting JVM krb5.conf to: {}",
                krb5conf.getAbsolutePath());
    }

    public void stop() {
        super.stop();
        System.getProperties().remove("java.security.krb5.conf");
        System.getProperties().remove("sun.security.krb5.debug");
        delete(workDir);
    }

    private void delete(File f) {
        if (f.isFile()) {
            if (! f.delete()) {
                logger.warn("WARNING: cannot delete file " + f.getAbsolutePath());
            }
        } else {
            for (File c: f.listFiles()) {
                delete(c);
            }
            if (! f.delete()) {
                logger.warn("WARNING: cannot delete directory " + f.getAbsolutePath());
            }
        }
    }

    public synchronized void createPrincipal(String principal, String password)
            throws Exception {
        Identity identity = new KrbIdentity(principal, password);
        getIdentityService().addIdentity(identity);
    }

    public void createPrincipals(String ... principals)
            throws Exception {
        String generatedPassword;
        for (String principal : principals) {
            generatedPassword = UUID.randomUUID().toString();
            principal = principal + "@" + getKdcRealm();
            createPrincipal(principal, generatedPassword);
        }
    }

    public void exportPrincipals(File keytabFile)
            throws Exception {
        Keytab keytab = new Keytab();
        List<KeytabEntry> entries = new ArrayList<KeytabEntry>();

        List<Identity> identities = getIdentityService().getIdentities();
        for (Identity identity : identities) {
            KrbIdentity ki = (KrbIdentity) identity;
            String principal = ki.getPrincipal();
            KerberosTime timestamp = new KerberosTime();
            for (Map.Entry<EncryptionType, EncryptionKey> entry : KerberosKeyFactory
                    .getKerberosKeys(principal, ki.getPassword()).entrySet()) {
                EncryptionKey ekey = entry.getValue();
                byte keyVersion = (byte) ekey.getKeyVersion();
                entries.add(new KeytabEntry(principal, 1L, timestamp, keyVersion,
                        ekey));
            }
        }
        keytab.setEntries(entries);
        keytab.write(keytabFile);
    }

    /*
    public static void main(String[] args) throws  Exception {
        if (args.length < 4) {
            System.out.println("Arguments: <WORKDIR> <MINIKDCPROPERTIES> " +
                    "<KEYTABFILE> [<PRINCIPALS>]+");
            System.exit(1);
        }
        File workDir = new File(args[0]);
        if (!workDir.exists()) {
            throw new RuntimeException("Specified work directory does not exists: "
                    + workDir.getAbsolutePath());
        }
        Properties conf = createConf();
        File file = new File(args[1]);
        if (!file.exists()) {
            throw new RuntimeException("Specified configuration does not exists: "
                    + file.getAbsolutePath());
        }
        Properties userConf = new Properties();
        userConf.load(new FileReader(file));
        for (Map.Entry entry : userConf.entrySet()) {
            conf.put(entry.getKey(), entry.getValue());
        }
        final TestKdcServer miniKdc = new TestKdcServer(conf, workDir);
        miniKdc.start();
        File krb5conf = new File(workDir, "krb5.conf");
        if (miniKdc.getKrb5conf().renameTo(krb5conf)) {
            File keytabFile = new File(args[2]).getAbsoluteFile();
            String[] principals = new String[args.length - 3];
            System.arraycopy(args, 3, principals, 0, args.length - 3);
            miniKdc.createPrincipal(keytabFile, principals);
            System.out.println();
            System.out.println("Standalone TestKdcServer Running");
            System.out.println("---------------------------------------------------");
            System.out.println("  Realm           : " + miniKdc.getRealm());
            System.out.println("  Running at      : " + miniKdc.getHost() + ":" +
                    miniKdc.getHost());
            System.out.println("  krb5conf        : " + krb5conf);
            System.out.println();
            System.out.println("  created keytab  : " + keytabFile);
            System.out.println("  with principals : " + Arrays.asList(principals));
            System.out.println();
            System.out.println(" Do <CTRL-C> or kill <PID> to stop it");
            System.out.println("---------------------------------------------------");
            System.out.println();
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    miniKdc.stop();
                }
            });
        } else {
            throw new RuntimeException("Cannot rename KDC's krb5conf to "
                    + krb5conf.getAbsolutePath());
        }
    } */
}