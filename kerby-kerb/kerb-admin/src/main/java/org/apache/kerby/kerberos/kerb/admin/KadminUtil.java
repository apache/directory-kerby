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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.KOptions;
import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * Kadmin utilities.
 */
public final class KadminUtil {

    private KadminUtil() { }

    static Kadmin createKadmin(File confDir) throws KrbException {
        KdcConfig kdcConfig;
        Conf backendConfig;

        File kdcConfFile = new File(confDir, "kdc.conf");
        kdcConfig = new KdcConfig();
        if (kdcConfFile.exists()) {
            try {
                kdcConfig.addIniConfig(kdcConfFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the kdc configuration file "
                    + kdcConfFile.getAbsolutePath());
            }
        }

        File backendConfigFile = new File(confDir, "backend.conf");
        backendConfig = new Conf();
        if (backendConfigFile.exists()) {
            try {
                backendConfig.addIniConfig(backendConfigFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the backend configuration file "
                    + backendConfigFile.getAbsolutePath());
            }
        }

        return new Kadmin(kdcConfig, backendConfig);
    }

    /**
     * Init the identity backend from backend configuration.
     */
    static IdentityBackend getBackend(Config backendConfig) {
        String backendClassName = backendConfig.getString(
            KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            throw new RuntimeException("Can not find the IdentityBackend class");
        }

        Class<?> backendClass;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Failed to load backend class: "
                    + backendClassName);
        }

        IdentityBackend backend;
        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
        return backend;
    }

    static void exportKeytab(File keytabFile, KrbIdentity identity)
        throws KrbException {

        Keytab keytab;
        try {
            if (!keytabFile.exists()) {
                if (!keytabFile.createNewFile()) {
                    throw new KrbException("Failed to create keytab file "
                        + keytabFile.getAbsolutePath());
                }
                keytab = new Keytab();
            } else {
                keytab = Keytab.loadKeytab(keytabFile);
            }
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        //Add principal to keytab.
        PrincipalName principal = identity.getPrincipal();
        KerberosTime timestamp = KerberosTime.now();
        for (EncryptionType encType : identity.getKeys().keySet()) {
            EncryptionKey ekey = identity.getKeys().get(encType);
            int keyVersion = ekey.getKvno();
            keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
        }

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Fail to store the keytab!", e);
        }
    }

    static void removeKeytabEntriesOf(File keytabFile,
                                             String principalName) throws KrbException {
        Keytab keytab;
        try {
            keytab = Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        keytab.removeKeytabEntries(new PrincipalName(principalName));

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to store keytab", e);
        }
    }

    static void removeKeytabEntriesOf(File keytabFile,
                                      String principalName, int kvno) throws KrbException {
        Keytab keytab;
        try {
            keytab = Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        keytab.removeKeytabEntries(new PrincipalName(principalName), kvno);

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to store keytab", e);
        }
    }

    static void removeOldKeytabEntriesOf(File keytabFile,
                                                String principalName) throws KrbException {
        Keytab keytab;
        try {
            keytab = Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        List<KeytabEntry> entries = keytab.getKeytabEntries(new PrincipalName(principalName));

        int maxKvno = 0;
        for (KeytabEntry entry : entries) {
            if (maxKvno < entry.getKvno()) {
                maxKvno = entry.getKvno();
            }
        }

        for(KeytabEntry entry : entries) {
            if(entry.getKvno() < maxKvno) {
                keytab.removeKeytabEntry(entry);
            }
        }

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to store keytab", e);
        }
    }

    static KrbIdentity createIdentity(String principal, KOptions kOptions)
        throws KrbException {
        KrbIdentity kid = new KrbIdentity(principal);
        kid.setCreatedTime(KerberosTime.now());
        if(kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            kid.setExpireTime(new KerberosTime(date.getTime()));
        } else {
            kid.setExpireTime(KerberosTime.NEVER);
        }
        if(kOptions.contains(KadminOption.KVNO)) {
            kid.setKeyVersion(kOptions.getIntegerOption(KadminOption.KVNO));
        } else {
            kid.setKeyVersion(1);
        }
        kid.setDisabled(false);
        kid.setLocked(false);

        return kid;
    }

    static void updateIdentity(KrbIdentity identity, KOptions kOptions) {
        if (kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            identity.setExpireTime(new KerberosTime(date.getTime()));
        }
        if (kOptions.contains(KadminOption.DISABLED)) {
            identity.setDisabled(kOptions.getBooleanOption(KadminOption.DISABLED));
        }
        if (kOptions.contains(KadminOption.LOCKED)) {
            identity.setLocked(kOptions.getBooleanOption(KadminOption.LOCKED));
        }
    }
}
