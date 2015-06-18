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
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.server.BackendConfig;
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
 * Server side admin facilities.
 */
public class Kadmin {

    private KdcConfig kdcConfig;
    private IdentityBackend backend;

    public Kadmin(KdcConfig kdcConfig, Config backendConfig) {
        this.kdcConfig = kdcConfig;
        backend = getBackend(backendConfig);
    }

    public Kadmin(Config backendConfig) {
        backend = getBackend(backendConfig);
    }

    /**
     * Set KDC config.
     * @param kdcConfig
     */
    public void setKdcConfig(KdcConfig kdcConfig) {
        this.kdcConfig = kdcConfig;
    }

    /**
     * Set backend config.
     * @param backendConfig
     */
    public void setBackendConfig(BackendConfig backendConfig) {
        backend = getBackend(backendConfig);
    }

    /**
     * Get identity service.
     * @return IdentityService
     */
    public IdentityService getIdentityService() {
        return backend;
    }

    /**
     * Init the identity backend from backend configuration.
     */
    public IdentityBackend getBackend(Config backendConfig) {
        String backendClassName = backendConfig.getString(
                KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            throw new RuntimeException("Can not find the IdentityBackend class");
        }

        Class<?> backendClass = null;
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

    public void addPrincipal(String principal, String password, KOptions kOptions)
        throws KrbException {

        KrbIdentity identity = createIdentity(principal, password, kOptions);
        try {
            backend.addIdentity(identity);
        } catch (RuntimeException e) {
            throw new KrbException("Fail to add principal.", e);
        }
    }

    private KrbIdentity createIdentity(String principal, String password, KOptions kOptions)
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
        kid.addKeys(generateKeys(kid.getPrincipalName(), password));

        return kid;
    }

    private List<EncryptionKey> generateKeys(String principal, String password)
        throws KrbException {
        try {
            return EncryptionUtil.generateKeys(principal, password, kdcConfig.getEncryptionTypes());
        } catch (KrbException e) {
            throw new KrbException("Failed to create keys", e);
        }
    }

    public StringBuffer addEntryToKeytab(File keytabFile, String principalName)
        throws KrbException {

        //Get Identity
        KrbIdentity identity = backend.getIdentity(principalName);
        if (identity == null) {
            throw new KrbException("Can not find the identity for pincipal " +
                    principalName + ".");
        }

        StringBuffer resultSB = new StringBuffer();
        Keytab keytab = loadKeytab(keytabFile);

        //Add principal to keytab.
        PrincipalName principal = identity.getPrincipal();
        KerberosTime timestamp = new KerberosTime();
        for (EncryptionType encType : identity.getKeys().keySet()) {
            EncryptionKey ekey = identity.getKeys().get(encType);
            int keyVersion = ekey.getKvno();
            keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
            resultSB.append("Entry for principal " + principalName +
                    " with kvno " + keyVersion + ", encryption type " +
                    encType.getName() + " added to keytab " +
                    keytabFile.getAbsolutePath() + "\n");
        }

        //Store the keytab
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Fail to store the keytab!", e);
        }
        return resultSB;
    }

    public StringBuilder removeEntryFromKeytab(File keytabFile, String principalName, String option)
        throws KrbException {
        int kvno;
        int numDeleted = 0;
        StringBuilder resultSB = new StringBuilder();
        Keytab keytab = loadKeytab(keytabFile);
        List<KeytabEntry> entries = keytab.getKeytabEntries(new PrincipalName(principalName));
        if (entries == null || entries.isEmpty()) {
            resultSB.append("Principal " + principalName + " not found! ");
            return resultSB;
        }

        if (option == null || option.equals("all")) {
            numDeleted = entries.size();
            for(KeytabEntry entry : entries) {
                keytab.removeKeytabEntry(entry);
            }
        } else if (option.equals("old")) {
            kvno = entries.get(0).getKvno();
            for (KeytabEntry entry : entries) {
                if (kvno > entry.getKvno()) {
                    kvno = entry.getKvno();
                }
            }
            numDeleted = deleteKeytabEntryByKvno(entries, kvno, keytab);
        } else {
            try {
                kvno = Integer.parseInt(option);
            } catch (NumberFormatException e) {
                resultSB.append("Parameter " + option + " not recognized!");
                return resultSB;
            }
            numDeleted = deleteKeytabEntryByKvno(entries, kvno, keytab);
        }

        //Store the keytab
        if (numDeleted != 0) {
            try {
                keytab.store(keytabFile);
            } catch (IOException e) {
                throw new KrbException("Fail to store the keytab!", e);
            }
        }

        resultSB.append( numDeleted + " entry(entries) removed for principal " +
                principalName + " from keytab \n");

        return resultSB;
    }

    private int deleteKeytabEntryByKvno(List<KeytabEntry> entries, int kvno, Keytab keytab) {
        int numDeleted = 0;
        for(KeytabEntry entry : entries) {
            if(entry.getKvno() == kvno) {
                numDeleted++;
                keytab.removeKeytabEntry(entry);
            }
        }
        return numDeleted;
    }

    private Keytab loadKeytab(File keytabFile) throws KrbException {
        try {
            if (!keytabFile.exists()) {
                keytabFile.createNewFile();
                return new Keytab();
            }

            return Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Fail to load keytab!", e);
        }
    }

    public void deletePrincipal(String principal) throws KrbException {
        try {
            backend.deleteIdentity(principal);
        } catch (RuntimeException e) {
            throw new KrbException("Fail to delete Identity!", e);
        }
    }

    public void modifyPrincipal(String principal, KOptions kOptions) throws KrbException {

        KrbIdentity originIdentity = backend.getIdentity(principal);
        if (originIdentity == null) {
            throw new KrbException("Principal \"" +
                originIdentity.getPrincipalName() + "\" does not exist.");
        }
        KrbIdentity identity = createUpdatedIdentity(originIdentity, kOptions);
        backend.updateIdentity(identity);
    }

    protected KrbIdentity createUpdatedIdentity(KrbIdentity kid, KOptions kOptions) {
        if (kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            kid.setExpireTime(new KerberosTime(date.getTime()));
        }
        if (kOptions.contains(KadminOption.DISABLED)) {
            kid.setDisabled(kOptions.getBooleanOption(KadminOption.DISABLED));
        }
        if (kOptions.contains(KadminOption.LOCKED)) {
            kid.setLocked(kOptions.getBooleanOption(KadminOption.LOCKED));
        }
        return kid;
    }

    public void renamePrincipal(String oldPrincipalName, String newPrincipalName)
        throws KrbException {

        KrbIdentity verifyIdentity = backend.getIdentity(newPrincipalName);
        if(verifyIdentity != null) {
            throw new KrbException("Principal \"" +
                verifyIdentity.getPrincipalName() + "\" is already exist.");
        }
        KrbIdentity identity = backend.getIdentity(oldPrincipalName);
        if (identity == null) {
            throw new KrbException("Principal \"" +
                oldPrincipalName + "\" does not exist.");
        }
        backend.deleteIdentity(oldPrincipalName);

        identity.setPrincipalName(newPrincipalName);
        identity.setPrincipal(new PrincipalName(newPrincipalName));
        backend.addIdentity(identity);
    }

    public KrbIdentity getPrincipal(String princName) throws KrbException {
        try {
            KrbIdentity identity = backend.getIdentity(princName);
            return identity;
        } catch (RuntimeException e) {
            throw new KrbException("Failed to get identity!", e);
        }
    }

    public List<String> listPrincipal() throws KrbException {
        try {
            List<String> principalNames = backend.getIdentities();
            return principalNames;
        } catch (RuntimeException e) {
            throw new KrbException("Failed to get identity!", e);
        }
    }
}
