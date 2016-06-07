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
package org.apache.kerby.kerberos.kerb.admin.kadmin.local;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.server.ServerSetting;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The implementation of admin side admin facilities for local mode.
 */
public class LocalKadminImpl implements LocalKadmin {
    private static final Logger LOG = LoggerFactory.getLogger(LocalKadminImpl.class);

    private final ServerSetting serverSetting;
    private final IdentityBackend backend;

    /**
     * Construct with prepared AdminServerConfig and BackendConfig.
     *
     * @param kdcConfig     The kdc config
     * @param backendConfig The backend config
     * @throws KrbException e
     */
    public LocalKadminImpl(KdcConfig kdcConfig,
                           BackendConfig backendConfig) throws KrbException {
        this.backend = KdcUtil.getBackend(backendConfig);
        this.serverSetting = new KdcSetting(kdcConfig, backendConfig);
    }

    //
    public LocalKadminImpl(ServerSetting serverSetting) throws KrbException {
        this.backend = KdcUtil.getBackend(serverSetting.getBackendConfig());
        this.serverSetting = serverSetting;
    }

    /**
     * Construct with prepared conf dir.
     *
     * @param confDir The path of conf dir
     * @throws KrbException e
     */
    public LocalKadminImpl(File confDir) throws KrbException {
        KdcConfig tmpKdcConfig = KdcUtil.getKdcConfig(confDir);
        if (tmpKdcConfig == null) {
            tmpKdcConfig = new KdcConfig();
        }

        BackendConfig tmpBackendConfig = KdcUtil.getBackendConfig(confDir);
        if (tmpBackendConfig == null) {
            tmpBackendConfig = new BackendConfig();
        }

        this.serverSetting = new KdcSetting(tmpKdcConfig, tmpBackendConfig);

        backend = KdcUtil.getBackend(tmpBackendConfig);
    }

    /**
     * Construct with prepared AdminServerSetting and Backend.
     *
     * @param kdcSetting The kdc setting
     * @param backend    The identity backend
     */
    public LocalKadminImpl(KdcSetting kdcSetting, IdentityBackend backend) {
        this.serverSetting = kdcSetting;
        this.backend = backend;
    }

    /**
     * Get the tgs principal name.
     */
    private String getTgsPrincipal() {
        return KrbUtil.makeTgsPrincipal(serverSetting.getKdcRealm()).getName();
    }

    // TODO: 2016/3/14 check whether it is possible to return getAdminServerRealm
    @Override
    public String getKadminPrincipal() {
        return KrbUtil.makeKadminPrincipal(serverSetting.getKdcRealm()).getName();
    }

    @Override
    public void checkBuiltinPrincipals() throws KrbException {
        String tgsPrincipal = getTgsPrincipal();
        String kadminPrincipal = getKadminPrincipal();
        if (backend.getIdentity(tgsPrincipal) == null
            || backend.getIdentity(kadminPrincipal) == null) {
            String errorMsg = "The built-in principals do not exist in backend,"
                + " please run the kdcinit tool.";
            LOG.error(errorMsg);
            throw new KrbException(errorMsg);
        }
    }

    @Override
    public void createBuiltinPrincipals() throws KrbException {
        String tgsPrincipal = getTgsPrincipal();
        if (backend.getIdentity(tgsPrincipal) == null) {
            addPrincipal(tgsPrincipal);
        } else {
            String errorMsg = "The tgs principal already exists in backend.";
            LOG.error(errorMsg);
            throw new KrbException(errorMsg);
        }

        String kadminPrincipal = getKadminPrincipal();
        if (backend.getIdentity(kadminPrincipal) == null) {
            addPrincipal(kadminPrincipal);
        } else {
            String errorMsg = "The kadmin principal already exists in backend.";
            LOG.error(errorMsg);
            throw new KrbException(errorMsg);
        }
    }

    @Override
    public void deleteBuiltinPrincipals() throws KrbException {
        deletePrincipal(getTgsPrincipal());
        deletePrincipal(getKadminPrincipal());
    }

    @Override
    public KdcConfig getKdcConfig() {
        return serverSetting.getKdcConfig();
    }

    @Override
    public BackendConfig getBackendConfig() {
        return serverSetting.getBackendConfig();
    }

    @Override
    public IdentityBackend getIdentityBackend() {
        return backend;
    }

    @Override
    public void addPrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, new KOptions());
    }

    @Override
    public void addPrincipal(String principal, KOptions kOptions)
            throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = AdminHelper.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
                getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
        System.out.println("add backend success"); //delete
    }

    @Override
    public void addPrincipal(String principal, String password)
            throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, password, new KOptions());
    }

    @Override
    public void addPrincipal(String principal, String password, KOptions kOptions)
            throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = AdminHelper.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, password,
                getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    @Override
    public void exportKeytab(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        List<String> principals = new ArrayList<>(1);
        principals.add(principal);
        exportKeytab(keytabFile, principals);
    }

    @Override
    public void exportKeytab(File keytabFile, List<String> principals)
            throws KrbException {
        //Get Identity
        List<KrbIdentity> identities = new LinkedList<>();
        for (String principal : principals) {
            KrbIdentity identity = backend.getIdentity(principal);
            if (identity == null) {
                throw new KrbException("Can not find the identity for pincipal "
                        + principal);
            }
            identities.add(identity);
        }

        AdminHelper.exportKeytab(keytabFile, identities);
    }

    @Override
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

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal);
    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal, int kvno)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal, kvno);
    }

    @Override
    public void removeOldKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeOldKeytabEntriesOf(keytabFile, principal);
    }

    @Override
    public void deletePrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        backend.deleteIdentity(principal);
    }

    @Override
    public void modifyPrincipal(String principal, KOptions kOptions)
            throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal \""
                    + principal + "\" does not exist.");
        }
        AdminHelper.updateIdentity(identity, kOptions);
        backend.updateIdentity(identity);
    }

    @Override
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

    @Override
    public KrbIdentity getPrincipal(String principalName) throws KrbException {
        KrbIdentity identity = backend.getIdentity(principalName);
        return identity;
    }

    @Override
    public List<String> getPrincipals() throws KrbException {
        Iterable<String> principalNames = backend.getIdentities();
        List<String> principalList = new LinkedList<>();
        Iterator<String> iterator = principalNames.iterator();
        while (iterator.hasNext()) {
            principalList.add(iterator.next());
        }
        return principalList;
    }

    @Override
    public List<String> getPrincipals(String globString) throws KrbException {
        Pattern pt = AdminHelper.getPatternFromGlobPatternString(globString);
        if (pt == null) {
            return getPrincipals();
        }

        Boolean containsAt = pt.pattern().indexOf('@') != -1;
        List<String> result = new LinkedList<>();

        List<String> principalNames = getPrincipals();
        for (String principal: principalNames) {
            String toMatch = containsAt ? principal : principal.split("@")[0];
            Matcher m = pt.matcher(toMatch);
            if (m.matches()) {
                result.add(principal);
            }
        }
        return result;
    }

    @Override
    public void changePassword(String principal,
                               String newPassword) throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = backend.getIdentity(principal);
        if (identity == null) {
            throw new KrbException("Principal " + principal
                    + "was not found. Please check the input and try again");
        }
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(principal, newPassword,
                getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);

        backend.updateIdentity(identity);
    }

    @Override
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

    @Override
    public void release() throws KrbException {
        if (backend != null) {
            backend.stop();
        }
    }

    /**
     * get size of principal
     */
    @Override
    public int size() throws KrbException {
        return this.getPrincipals().size();
    }

    /**
     * Fix principal name, making it complete.
     *
     * @param principal The principal name
     */
    private String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + serverSetting.getKdcRealm();
        }
        return principal;
    }
}
