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
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Server side admin facilities.
 */
public class Kadmin {
    private static final Logger LOG = LoggerFactory.getLogger(Kadmin.class);

    private final KdcSetting kdcSetting;
    private final IdentityBackend backend;

    /**
     * Construct with prepared KdcConfig and BackendConfig.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param kdcConfig     The kdc config
     * @param backendConfig The backend config
     */
    public Kadmin(KdcConfig kdcConfig,
                  BackendConfig backendConfig) throws KrbException {
        this.backend = KdcUtil.getBackend(backendConfig);
        this.kdcSetting = new KdcSetting(kdcConfig, backendConfig);
    }

    /**
     * Construct with prepared conf dir.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e;
     * @param confDir The path of conf dir
     */
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

    /**
     * Construct with prepared KdcSetting and Backend.
     *
     * @param kdcSetting The kdc setting
     * @param backend    The identity backend
     */
    public Kadmin(KdcSetting kdcSetting, IdentityBackend backend) {
        this.kdcSetting = kdcSetting;
        this.backend = backend;
    }

    /**
     * Get the tgs principal name.
     *
     * @return The tgs principal name.
     */
    private String getTgsPrincipal() {
        return KrbUtil.makeTgsPrincipal(kdcSetting.getKdcRealm()).getName();
    }

    /**
     * Get the kadmin principal name.
     *
     * @return The kadmin principal name.
     */
    public String getKadminPrincipal() {
        return KrbUtil.makeKadminPrincipal(kdcSetting.getKdcRealm()).getName();
    }

    /**
     * Check the built-in principals, will throw KrbException if not exist.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
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

    /**
     * Create build-in principals.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
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

    /**
     * Delete build-in principals.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void deleteBuiltinPrincipals() throws KrbException {
        deletePrincipal(getTgsPrincipal());
        deletePrincipal(getKadminPrincipal());
    }

    /**
     * Get kdc config.
     *
     * @return The kdc config.
     */
    public KdcConfig getKdcConfig() {
        return kdcSetting.getKdcConfig();
    }

    /**
     * Get backend config.
     *
     * @return The backend config.
     */
    public BackendConfig getBackendConfig() {
        return kdcSetting.getBackendConfig();
    }

    /**
     * Get identity backend.
     *
     * @return IdentityBackend
     */
    public IdentityBackend getIdentityBackend() {
        return backend;
    }

    /**
     * Add principal to backend.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param principal The principal to be added into backend
     */
    public void addPrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, new KOptions());
    }

    /**
     * Add principal to backend.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param principal The principal to be added into backend
     * @param kOptions The KOptions with principal info
     */
    public void addPrincipal(String principal, KOptions kOptions)
            throws KrbException {
        principal = fixPrincipal(principal);
        KrbIdentity identity = AdminHelper.createIdentity(principal, kOptions);
        List<EncryptionKey> keys = EncryptionUtil.generateKeys(
                getKdcConfig().getEncryptionTypes());
        identity.addKeys(keys);
        backend.addIdentity(identity);
    }

    /**
     * Add principal to backend.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param principal The principal to be added into backend
     * @param password  The password to create encryption key
     */
    public void addPrincipal(String principal, String password)
            throws KrbException {
        principal = fixPrincipal(principal);
        addPrincipal(principal, password, new KOptions());
    }

    /**
     * Add principal to backend.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param principal The principal to be added into backend
     * @param password  The password to create encryption key
     * @param kOptions  The KOptions with principal info
     */
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
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    public void exportKeytab(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        List<String> principals = new ArrayList<>(1);
        principals.add(principal);
        exportKeytab(keytabFile, principals);
    }

    /**
     * Export all the keys of the specified principals into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principals The principal names
     * @throws KrbException e
     */
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

    /**
     * Export all identity keys to the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @throws KrbException e
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

    /**
     * Remove all the keys of the specified principal in the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    public void removeKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal);
    }

    /**
     * Remove all the keys of the specified principal with specified kvno
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @param kvno The kvno
     * @throws KrbException e
     */
    public void removeKeytabEntriesOf(File keytabFile, String principal, int kvno)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeKeytabEntriesOf(keytabFile, principal, kvno);
    }

    /**
     * Remove all the old keys of the specified principal
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    public void removeOldKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException {
        principal = fixPrincipal(principal);
        AdminHelper.removeOldKeytabEntriesOf(keytabFile, principal);
    }

    /**
     * Delete the principal in backend.
     *
     * @param principal The principal to be deleted from backend
     * @throws KrbException e
     */
    public void deletePrincipal(String principal) throws KrbException {
        principal = fixPrincipal(principal);
        backend.deleteIdentity(principal);
    }

    /**
     * Modify the principal with KOptions.
     *
     * @param principal The principal to be modified
     * @param kOptions The KOptions with changed principal info
     * @throws KrbException e
     */
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

    /**
     * Rename the principal.
     *
     * @param oldPrincipalName The original principal name
     * @param newPrincipalName The new principal name
     * @throws KrbException e
     */
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

    /**
     * Get the identity from backend.
     *
     * @param principalName The principal name
     * @throws KrbException e
     * @return identity
     */
    public KrbIdentity getPrincipal(String principalName) throws KrbException {
        KrbIdentity identity = backend.getIdentity(principalName);
        return identity;
    }

    /**
     * Get all the principal names from backend.
     *
     * @throws KrbException e
     * @return principal list
     */
    public List<String> getPrincipals() throws KrbException {
        Iterable<String> principalNames = backend.getIdentities();
        List<String> principalList = new LinkedList<>();
        Iterator<String> iterator = principalNames.iterator();
        while (iterator.hasNext()) {
            principalList.add(iterator.next());
        }
        return principalList;
    }

    /**
     * Get all the Pattern for matching from glob string. The glob string can contain "." "*" and "[]"
     *
     * @param globString The glob string for matching
     * @throws KrbException e
     * @return pattern
     */
    public Pattern getPatternFromGlobPatternString(String globString) throws KrbException
    {
        if (globString == null || globString.equals("")) {
            return null;
        }
        if (!Pattern.matches("^[0-9A-Za-z._/@*?\\[\\]\\-]+$", globString)) {
            throw new KrbException("Glob pattern string contains invalid character!");
        }
        String patternString = globString;
        patternString = patternString.replaceAll("\\.", "\\\\.");
        patternString = patternString.replaceAll("\\?", ".");
        patternString = patternString.replaceAll("\\*", ".*");
        patternString = "^" + patternString + "$";

        Pattern pt;
        try {
            pt = Pattern.compile(patternString);
        } catch (PatternSyntaxException e) {
            throw new KrbException("Invalid glob pattern string!");
        }
        return pt;
    }

    /**
     * Get all the principal names that meets the pattern
     *
     * @param pt The pattern for matching
     * @throws KrbException e
     * @return Principal names
     */
    public List<String> getPrincipalNamesByPattern(Pattern pt) throws KrbException {
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

    /**
     * Update the password of specified principal.
     *
     * @param principal The principal to be updated password
     * @param password The new password
     * @throws KrbException e
     */
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

    /**
     * Update the random keys of specified principal.
     *
     * @param principal The principal to be updated keys
     * @throws KrbException e
     */
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

    /**
     * Stop the backend and release any resources associated.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    public void release() throws KrbException {
        if (backend != null) {
            backend.stop();
        }
    }

    /**
     * Fix principal name.
     *
     * @param principal The principal name
     * @throws KrbException
     */
    private String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + kdcSetting.getKdcRealm();
        }
        return principal;
    }
}
