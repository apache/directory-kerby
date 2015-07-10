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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.File;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * Server side admin facilities.
 */
public class Kadmin {
    private final KdcSetting kdcSetting;
    private final IdentityService backend;

    public Kadmin(KdcConfig kdcConfig,
                  BackendConfig backendConfig) throws KrbException {
        this.backend = KdcUtil.getBackend(backendConfig);
        this.kdcSetting = new KdcSetting(kdcConfig, backendConfig);
    }

    public Kadmin(File confDir) throws KrbException {
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }

        this.kdcSetting = new KdcSetting(tmpKdcConfig, tmpBackendConfig);

        backend = KdcUtil.getBackend(tmpBackendConfig);
    }

    public Kadmin(KdcSetting kdcSetting, IdentityService backend) {
        this.kdcSetting = kdcSetting;
        this.backend = backend;
    }

    private String getTgsPrincipal() {
        return KrbUtil.makeTgsPrincipal(kdcSetting.getKdcRealm()).getName();
    }

    private String getKadminPrincipal() {
        return KrbUtil.makeKadminPrincipal(kdcSetting.getKdcRealm()).getName();
    }

    public void createBuiltinPrincipals() throws KrbException {
        String tgsPrincipal = getTgsPrincipal();
        if (backend.getIdentity(tgsPrincipal) == null) {
            addPrincipal(tgsPrincipal);
        }

        String kadminPrincipal = getKadminPrincipal();
        if (backend.getIdentity(kadminPrincipal) == null) {
            addPrincipal(kadminPrincipal);
        }
    }

    public void deleteBuiltinPrincipals() throws KrbException {
        deletePrincipal(getTgsPrincipal());
        deletePrincipal(getKadminPrincipal());
    }

    public KdcConfig getKdcConfig() {
        return kdcSetting.getKdcConfig();
    }

    public BackendConfig getBackendConfig() {
        return kdcSetting.getBackendConfig();
    }

    /**
     * Get identity backend.
     * @return IdentityBackend
     */
    public IdentityService getIdentityBackend() {
        return backend;
    }

    public void addPrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, new KOptions());
    }

    public void addPrincipal(String principal, KOptions kOptions)
        throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = AdminHelper.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
                getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    public void addPrincipal(String principal, String password)
            throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, password, new KOptions());
    }

    public void addPrincipal(String principal, String password, KOptions kOptions)
        throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = AdminHelper.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, password,
            getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    /**
     * Export all the keys of the specified principal into the specified keytab
     * file.
     * @param keytabFile
     * @param principal
     * @throws KrbException
     */
    public void exportKeytab(File keytabFile, String principal)
        throws KrbException {
        principal = fixPrincipal(principal);
        //Get Identity
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Can not find the identity for pincipal "
                    + principal);
        }

        AdminHelper.exportKeytab(keytabFile, identity);
    }

    /**
     * Export all identity keys to the specified keytab file.
     * @param keytabFile
     * @throws KrbException
     */
    public void exportKeytab(File keytabFile) throws KrbException {
        Keytab keytab = AdminHelper.createOrLoadKeytab(keytabFile);

        Iterable<String> principals = backend.getIdentities();
        for (String principal : principals) {
            KrbIdentity identity = backend.getIdentity(principal);
            if (identity != null) {
                AdminHelper.exportToKeytab(keytab, identity);
            }
        }

        AdminHelper.storeKeytab(keytab, keytabFile);
    }

    public void removeKeytabEntriesOf(File keytabFile, String principal)
        throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal);
    }

    public void removeKeytabEntriesOf(File keytabFile, String principal, int kvno)
        throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal, kvno);
    }

    public void removeOldKeytabEntriesOf(File keytabFile, String principal)
        throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeOldKeytabEntriesOf(keytabFile, principal);
    }

    public void deletePrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        backend.deleteIdentity(principal);
    }

    public void modifyPrincipal(String principal, KOptions kOptions)
        throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal \""
                    + identity.getPrincipalName() + "\" does not exist.");
        }
        AdminHelper.updateIdentity(identity, kOptions);
        backend.updateIdentity(identity);
    }

    public void renamePrincipal(String oldPrincipalName, String newPrincipalName)
        throws KrbException {
        oldPrincipalName = fixPrincipal(oldPrincipalName);
        newPrincipalName = fixPrincipal(newPrincipalName);
        KrbIdentity oldIdentity = backend.getIdentity(newPrincipalName);
        if (oldIdentity != null) {
            throw new KrbException("Principal \""
                    + oldIdentity.getPrincipalName() + "\" is already exist.");
        }
        KrbIdentity identity = backend.getIdentity(oldPrincipalName);
        if (identity == null) {
            throw new KrbException("Principal \""
                    + oldPrincipalName + "\" does not exist.");
        }
        backend.deleteIdentity(oldPrincipalName);

        identity.setPrincipalName(newPrincipalName);
        identity.setPrincipal(new PrincipalName(newPrincipalName));
        backend.addIdentity(identity);
    }

    public KrbIdentity getPrincipal(String principalName) throws KrbException {
        KrbIdentity identity = backend.getIdentity(principalName);
        return identity;
    }

    public List<String> getPrincipals() throws KrbException {
        Iterable<String> principalNames = backend.getIdentities();
        List<String> principalList = new LinkedList<>();
        Iterator<String> iterator = principalNames.iterator();
        while (iterator.hasNext()) {
            principalList.add(iterator.next());
        }
        return principalList;
    }

    public void updatePassword(String principal, String password)
        throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal " + principal
                    + "was not found. Please check the input and try again");
        }
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, password,
            getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);

        backend.updateIdentity(identity);
    }

    public void updateKeys(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal " + principal
                    + "was not found. Please check the input and try again");
        }
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
            getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.updateIdentity(identity);
    }

    private String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + getKdcConfig().getKdcRealm();
        }
        return principal;
    }
}
