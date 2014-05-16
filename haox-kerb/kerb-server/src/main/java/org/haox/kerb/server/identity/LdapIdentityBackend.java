package org.haox.kerb.server.identity;

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
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;

public abstract class LdapIdentityBackend extends AbstractIdentityBackend {
    private static final Logger logger = LoggerFactory.getLogger(LdapIdentityBackend.class);

    private String searchBaseDn;
    private DirectoryService directoryService;
    private ReplayCheckService replayCache;
    private File workDir;

    public LdapIdentityBackend() {
        super();
    }



    private void initDirectoryService() throws Exception {
        directoryService = new DefaultDirectoryService();
        directoryService.setInstanceLayout(new InstanceLayout(workDir));

        CacheService cacheService = new CacheService();
        directoryService.setCacheService(cacheService);

        // first load the schema
        InstanceLayout instanceLayout = directoryService.getInstanceLayout();
        File schemaPartitionDirectory = new File(
                instanceLayout.getPartitionsDirectory(), "schema");
        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(
                instanceLayout.getPartitionsDirectory());
        extractor.extractOrCopy();

        SchemaLoader loader = new LdifSchemaLoader(schemaPartitionDirectory);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);
        schemaManager.loadAllEnabled();
        directoryService.setSchemaManager(schemaManager);
        // Init the LdifPartition with schema
        LdifPartition schemaLdifPartition = new LdifPartition(schemaManager);
        schemaLdifPartition.setPartitionPath(schemaPartitionDirectory.toURI());

        // The schema partition
        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(schemaLdifPartition);
        directoryService.setSchemaPartition(schemaPartition);

        JdbmPartition systemPartition = new JdbmPartition(directoryService.getSchemaManager());
        systemPartition.setId("system");
        systemPartition.setPartitionPath(new File(
                directoryService.getInstanceLayout().getPartitionsDirectory(),
                systemPartition.getId()).toURI());
        systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
        systemPartition.setSchemaManager(directoryService.getSchemaManager());
        directoryService.setSystemPartition(systemPartition);

        directoryService.getChangeLog().setEnabled(false);
        directoryService.setDenormalizeOpAttrsEnabled(true);
        directoryService.addLast(new KeyDerivationInterceptor());

        String orgDn = null;//kdcConfig.getKdcDn();
        String orgDomain = null;//kdcConfig.getKdcDomain();
        JdbmPartition partition = new JdbmPartition(directoryService.getSchemaManager());
        partition.setId(orgDomain);
        partition.setPartitionPath(new File(
                directoryService.getInstanceLayout().getPartitionsDirectory(), orgDomain).toURI());
        partition.setSuffixDn(new Dn(orgDn));
        directoryService.addPartition(partition);

        // indexes
        Set indexedAttributes = new HashSet();
        indexedAttributes.add(new JdbmIndex<String, Entry>("objectClass", false));
        indexedAttributes.add(new JdbmIndex<String, Entry>("dc", false));
        indexedAttributes.add(new JdbmIndex<String, Entry>("ou", false));
        partition.setIndexedAttributes(indexedAttributes);

        // And start the ds
        directoryService.setInstanceId(orgDomain);
        directoryService.startup();
        // context entry, after ds.startup()
        Dn dn = new Dn(orgDn);
        Entry entry = directoryService.newEntry(dn);
        entry.add("objectClass", "top", "domain");
        //entry.add("dc", orgName);
        directoryService.getAdminSession().add(entry);
    }

    private void initKDCServer() throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        InputStream is = cl.getResourceAsStream("kdc.ldiff");

        SchemaManager schemaManager = directoryService.getSchemaManager();
        //final String content = StrSubstitutor.replace(IOUtils.toString(is), map);
        String content = null;
        LdifReader reader = new LdifReader(new StringReader(content));
        for (LdifEntry ldifEntry : reader) {
            directoryService.getAdminSession().add(new DefaultEntry(schemaManager,
                    ldifEntry.getEntry()));
        }
    }
}