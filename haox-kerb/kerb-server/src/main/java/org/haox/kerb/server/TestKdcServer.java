package org.haox.kerb.server;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schemaextractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaextractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaloader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schemamanager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.reflect.Method;
import java.text.MessageFormat;
import java.util.*;

public class TestKdcServer extends KdcServer {
    private static final Logger logger = LoggerFactory.getLogger(TestKdcServer.class);

    private File workDir;
    private File krb5conf;

    /**
     * Creates a TestKdcServer.
     *
     * @param conf TestKdcServer configuration.
     * @param workDir working directory, it should be the build directory. Under
     * this directory an ApacheDS working directory will be created, this
     * directory will be deleted when the TestKdcServer stops.
     * @throws Exception thrown if the TestKdcServer could not be created.
     */
    public TestKdcServer(Properties conf, File workDir) throws Exception {
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

    /**
     * Starts the TestKdcServer.
     *
     * @throws Exception thrown if the TestKdcServer could not be started.
     */
    public synchronized void start() throws Exception {
        initDirectoryService();
        initKDCServer();
    }

    private void initKDCServer() throws Exception {
        StringBuilder sb = new StringBuilder();
        is = cl.getResourceAsStream("minikdc-krb5.conf");
        BufferedReader r = new BufferedReader(new InputStreamReader(is));
        String line = r.readLine();
        while (line != null) {
            sb.append(line).append("{3}");
            line = r.readLine();
        }
        r.close();
        krb5conf = new File(workDir, "krb5.conf").getAbsoluteFile();
        FileUtils.writeStringToFile(krb5conf,
                MessageFormat.format(sb.toString(), getRealm(), getHost(),
                        Integer.toString(getPort()), System.getProperty("line.separator")));
        System.setProperty("java.security.krb5.conf", krb5conf.getAbsolutePath());

        System.setProperty("sun.security.krb5.debug", conf.getProperty(DEBUG,
                "false"));

        // refresh the org.haox.config
        Class<?> classRef;
        if (System.getProperty("java.vendor").contains("IBM")) {
            classRef = Class.forName("com.ibm.security.krb5.internal.ConfigImpl");
        } else {
            classRef = Class.forName("sun.security.krb5.ConfigImpl");
        }
        Method refreshMethod = classRef.getMethod("refresh", new Class[0]);
        refreshMethod.invoke(classRef, new Object[0]);

        logger.info("TestKdcServer listening at port: {}", getPort());
        logger.info("TestKdcServer setting JVM krb5.conf to: {}",
                krb5conf.getAbsolutePath());
    }

    /**
     * Stops the TestKdcServer
     * @throws Exception
     */
    public synchronized void stop() {
        if (kdc != null) {
            System.getProperties().remove("java.security.krb5.conf");
            System.getProperties().remove("sun.security.krb5.debug");
            kdc.stop();
            try {
                ds.shutdown();
            } catch (Exception ex) {
                logger.error("Could not shutdown ApacheDS properly: {}", ex.toString(),
                        ex);
            }
        }
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

    /**
     * Creates a principal in the KDC with the specified user and password.
     *
     * @param principal principal name, do not include the domain.
     * @param password password.
     * @throws Exception thrown if the principal could not be created.
     */
    public synchronized void createPrincipal(String principal, String password)
            throws Exception {
        String orgName= conf.getProperty(ORG_NAME);
        String orgDomain = conf.getProperty(ORG_DOMAIN);
        String baseDn = "ou=users,dc=" + orgName.toLowerCase() + ",dc=" +
                orgDomain.toLowerCase();
        String content = "dn: uid=" + principal + "," + baseDn + "\n" +
                "objectClass: top\n" +
                "objectClass: person\n" +
                "objectClass: inetOrgPerson\n" +
                "objectClass: krb5principal\n" +
                "objectClass: krb5kdcentry\n" +
                "cn: " + principal + "\n" +
                "sn: " + principal + "\n" +
                "uid: " + principal + "\n" +
                "userPassword: " + password + "\n" +
                "krb5PrincipalName: " + principal + "@" + getRealm() + "\n" +
                "krb5KeyVersionNumber: 0";

        for (LdifEntry ldifEntry : new LdifReader(new StringReader(content))) {
            ds.getAdminSession().add(new DefaultEntry(ds.getSchemaManager(),
                    ldifEntry.getEntry()));
        }
    }

    /**
     * Creates  multiple principals in the KDC and adds them to a keytab file.
     *
     * @param keytabFile keytab file to add the created principal.s
     * @param principals principals to add to the KDC, do not include the domain.
     * @throws Exception thrown if the principals or the keytab file could not be
     * created.
     */
    public void createPrincipal(File keytabFile, String ... principals)
            throws Exception {
        String generatedPassword = UUID.randomUUID().toString();
        Keytab keytab = new Keytab();
        List<KeytabEntry> entries = new ArrayList<KeytabEntry>();
        for (String principal : principals) {
            createPrincipal(principal, generatedPassword);
            principal = principal + "@" + getRealm();
            KerberosTime timestamp = new KerberosTime();
            for (Map.Entry<EncryptionType, EncryptionKey> entry : KerberosKeyFactory
                    .getKerberosKeys(principal, generatedPassword).entrySet()) {
                EncryptionKey ekey = entry.getValue();
                byte keyVersion = (byte) ekey.getKeyVersion();
                entries.add(new KeytabEntry(principal, 1L, timestamp, keyVersion,
                        ekey));
            }
        }
        keytab.setEntries(entries);
        keytab.write(keytabFile);
    }

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
    }
}