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
import org.apache.kerby.kerberos.kerb.admin.kadmin.KadminOption;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * LocalKadmin utilities.
 */
public final class AdminHelper {

    private AdminHelper() { }

    /**
     * Export all the keys of the specified principal into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param identity  The identity
     * @throws KrbException If there is a problem exporting the keys of the specified principal
     */
    public static void exportKeytab(File keytabFile, KrbIdentity identity)
            throws KrbException {

        Keytab keytab = createOrLoadKeytab(keytabFile);

        exportToKeytab(keytab, identity);

        storeKeytab(keytab, keytabFile);
    }

    /**
     * Export all the keys of the specified principal into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param identities  Identities to export to keytabFile
     * @throws KrbException If there is a problem exporting the keys of the specified principal
     */
    public static void exportKeytab(File keytabFile, List<KrbIdentity> identities)
            throws KrbException {

        Keytab keytab = createOrLoadKeytab(keytabFile);

        for (KrbIdentity identity : identities) {
            exportToKeytab(keytab, identity);
        }

        storeKeytab(keytab, keytabFile);
    }

    /**
     * Load keytab from keytab file.
     *
     * @param keytabFile The keytab file
     * @return The keytab load from keytab file
     * @throws KrbException If there is a problem loading the keytab
     */
    public static Keytab loadKeytab(File keytabFile) throws KrbException {
        Keytab keytab;
        try {
            keytab = Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        return keytab;
    }

    /**
     * Load keytab from Input stream.
     *
     * @param keytabInputStream The Input stream
     * @return The keytab load from keytab file
     * @throws KrbException If there is a problem loading the Input stream
     */
    public static Keytab loadKeytab(InputStream keytabInputStream) throws KrbException {
        Keytab keytab;
        try {
            keytab = Keytab.loadKeytab(keytabInputStream);
        } catch (IOException e) {
            throw new KrbException("Failed to load keytab", e);
        }

        return keytab;
    }

    /**
     * If keytab file does not exist, create a new keytab,
     * otherwise load keytab from keytab file.
     *
     * @param keytabFile The keytab file
     * @return The keytab load from keytab file
     * @throws KrbException If there is a problem creating or loading the keytab
     */
    public static Keytab createOrLoadKeytab(File keytabFile) throws KrbException {

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
            throw new KrbException("Failed to load or create keytab "
                + keytabFile.getAbsolutePath(), e);
        }

        return keytab;
    }

    /**
     * Export all the keys of the specified identity into the keytab.
     *
     * @param keytab The keytab
     * @param identity  The identity
     * @throws KrbException If there is a problem exporting the identity to the keytab
     */
    public static void exportToKeytab(Keytab keytab, KrbIdentity identity)
        throws KrbException {

        //Add principal to keytab.
        PrincipalName principal = identity.getPrincipal();
        KerberosTime timestamp = KerberosTime.now();
        for (EncryptionType encType : identity.getKeys().keySet()) {
            EncryptionKey ekey = identity.getKeys().get(encType);
            int keyVersion = ekey.getKvno();
            keytab.addEntry(new KeytabEntry(principal, timestamp, keyVersion, ekey));
        }
    }

    /**
     * Store the keytab to keytab file.
     *
     * @param keytab   The keytab
     * @param keytabFile The keytab file
     * @throws KrbException If there is a problem storing the keytab
     */
    public static void storeKeytab(Keytab keytab, File keytabFile) throws KrbException {
        try {
            keytab.store(keytabFile);
        } catch (IOException e) {
            throw new KrbException("Failed to store keytab", e);
        }
    }

    /**
     * Remove all the keys of the specified principal in the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principalName  The principal name
     * @throws KrbException If there is a problem removing the keys of the specified principal
     */
    public static void removeKeytabEntriesOf(File keytabFile,
                                             String principalName) throws KrbException {
        Keytab keytab = loadKeytab(keytabFile);

        keytab.removeKeytabEntries(new PrincipalName(principalName));

        storeKeytab(keytab, keytabFile);
    }

    /**
     * Remove all the keys of the specified principal with specified kvno
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principalName  The principal name
     * @param kvno The kvno
     * @throws KrbException If there is a problem removing the keys of the specified principal
     */
    static void removeKeytabEntriesOf(File keytabFile,
                                      String principalName, int kvno) throws KrbException {
        Keytab keytab = loadKeytab(keytabFile);

        keytab.removeKeytabEntries(new PrincipalName(principalName), kvno);

        storeKeytab(keytab, keytabFile);
    }

    /**
     * Remove all the old keys of the specified principal
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principalName  The principal name
     * @throws KrbException If there is a problem in removing the old keys of the specified principal
     */
    public static void removeOldKeytabEntriesOf(File keytabFile,
                                                String principalName) throws KrbException {
        Keytab keytab = loadKeytab(keytabFile);

        List<KeytabEntry> entries = keytab.getKeytabEntries(
                new PrincipalName(principalName));

        int maxKvno = 0;
        for (KeytabEntry entry : entries) {
            if (maxKvno < entry.getKvno()) {
                maxKvno = entry.getKvno();
            }
        }

        for (KeytabEntry entry : entries) {
            if (entry.getKvno() < maxKvno) {
                keytab.removeKeytabEntry(entry);
            }
        }

        storeKeytab(keytab, keytabFile);
    }

    /**
     * Create principal.
     *
     * @param principal The principal name to be created
     * @param kOptions  The KOptions with principal info
     * @return the created principal identity
     * @throws KrbException If there is a problem in creating the principal
     */
    public static KrbIdentity createIdentity(String principal, KOptions kOptions)
        throws KrbException {
        KrbIdentity kid = new KrbIdentity(principal);
        kid.setCreatedTime(KerberosTime.now());
        if (kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            kid.setExpireTime(new KerberosTime(date.getTime()));
        } else {
            kid.setExpireTime(new KerberosTime(253402300799900L));
        }
        if (kOptions.contains(KadminOption.KVNO)) {
            kid.setKeyVersion(kOptions.getIntegerOption(KadminOption.KVNO));
        } else {
            kid.setKeyVersion(1);
        }
        kid.setDisabled(false);
        kid.setLocked(false);

        return kid;
    }

    /**
     * Modify the principal with KOptions.
     *
     * @param identity The identity to be modified
     * @param kOptions  The KOptions with changed principal info
     */
    public static void updateIdentity(KrbIdentity identity, KOptions kOptions) {
        if (kOptions.contains(KadminOption.EXPIRE)) {
            Date date = kOptions.getDateOption(KadminOption.EXPIRE);
            identity.setExpireTime(new KerberosTime(date.getTime()));
        }
        if (kOptions.contains(KadminOption.DISABLED)) {
            identity.setDisabled(kOptions.getBooleanOption(KadminOption.DISABLED, false));
        }
        if (kOptions.contains(KadminOption.LOCKED)) {
            identity.setLocked(kOptions.getBooleanOption(KadminOption.LOCKED, false));
        }
    }

    /**
     * Get all the Pattern for matching from glob string.
     * The glob string can contain "." "*" and "[]"
     *
     * @param globString The glob string for matching
     * @return pattern
     * @throws KrbException If there is a problem in compiling the pattern string
     */
    public static Pattern getPatternFromGlobPatternString(String globString) throws KrbException {
        if (globString == null || globString.equals("")) {
            return null;
        }
        if (!Pattern.matches("^[0-9A-Za-z._/@*?\\[\\]\\-]+$", globString)) {
            throw new KrbException("Glob pattern string contains invalid character");
        }

        String patternString = globString;
        patternString = patternString.replaceAll("\\.", "\\\\.");
        patternString = patternString.replaceAll("\\?", ".");
        patternString = patternString.replaceAll("\\*", ".*");
        patternString = "^" + patternString + "$";

        try {
            return Pattern.compile(patternString);
        } catch (PatternSyntaxException e) {
            throw new KrbException("Invalid glob pattern string");
        }
    }
}
