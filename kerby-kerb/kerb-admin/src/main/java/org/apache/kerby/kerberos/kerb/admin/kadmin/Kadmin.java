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
package org.apache.kerby.kerberos.kerb.admin.kadmin;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.File;
import java.util.List;

/**
 * Server side admin facilities from remote, similar to MIT kadmin remote mode.
 */
public interface Kadmin {

    /**
     * Get the kadmin principal name.
     *
     * @return The kadmin principal name.
     */
    String getKadminPrincipal();

    /**
     * Add principal to backend.
     *
     * @param principal The principal to be added into backend
     * @throws KrbException e
     */
    void addPrincipal(String principal) throws KrbException;

    /**
     * Add principal to backend.
     *
     * @par am principal The principal to be added into backend
     * @param kOptions The KOptions with principal info
     * @throws KrbException e
     */
    void addPrincipal(String principal, KOptions kOptions) throws KrbException;

    /**
     * Add principal to backend.
     *
     * @param principal The principal to be added into backend
     * @param password  The password to create encryption key
     * @throws KrbException e
     */
    void addPrincipal(String principal, String password) throws KrbException;

    /**
     * Add principal to backend.
     *
     * @param principal The principal to be added into backend
     * @param password  The password to create encryption key
     * @param kOptions  The KOptions with principal info
     * @throws KrbException e
     */
    void addPrincipal(String principal, String password,
                      KOptions kOptions) throws KrbException;

    /**
     * Export all the keys of the specified principal into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    void exportKeytab(File keytabFile, String principal) throws KrbException;

    /**
     * Export all the keys of the specified principals into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principals The principal names
     * @throws KrbException e
     */
    void exportKeytab(File keytabFile,
                      List<String> principals) throws KrbException;

    /**
     * Export all identity keys to the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @throws KrbException e
     */
    void exportKeytab(File keytabFile) throws KrbException;

    /**
     * Remove all the keys of the specified principal in the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    void removeKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException;

    /**
     * Remove all the keys of the specified principal with specified kvno
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @param kvno The kvno
     * @throws KrbException e
     */
    void removeKeytabEntriesOf(File keytabFile, String principal, int kvno)
            throws KrbException;

    /**
     * Remove all the old keys of the specified principal
     * in the specified keytab file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws KrbException e
     */
    void removeOldKeytabEntriesOf(File keytabFile, String principal)
            throws KrbException;

    /**
     * Delete the principal in backend.
     *
     * @param principal The principal to be deleted from backend
     * @throws KrbException e
     */
    void deletePrincipal(String principal) throws KrbException;

    /**
     * Modify the principal with KOptions.
     *
     * @param principal The principal to be modified
     * @param kOptions The KOptions with changed principal info
     * @throws KrbException e
     */
    void modifyPrincipal(String principal, KOptions kOptions) throws KrbException;

    /**
     * Rename the principal.
     *
     * @param oldPrincipalName The original principal name
     * @param newPrincipalName The new principal name
     * @throws KrbException e
     */
    void renamePrincipal(String oldPrincipalName,
                         String newPrincipalName) throws KrbException;

    /**
     * Get all the principal names from backend.
     *
     * @return principal list
     * @throws KrbException e
     */
    List<String> getPrincipals() throws KrbException;

    /**
     * Get all the principal names that meets the pattern
     *
     * @param globString The glob string for matching
     * @return Principal names
     * @throws KrbException e
     */
    List<String> getPrincipals(String globString) throws KrbException;

    /**
     * Change the password of specified principal.
     *
     * @param principal The principal to be updated password
     * @param newPassword The new password
     * @throws KrbException e
     */
    void changePassword(String principal, String newPassword) throws KrbException;

    /**
     * Update the random keys of specified principal.
     *
     * @param principal The principal to be updated keys
     * @throws KrbException e
     */
    void updateKeys(String principal) throws KrbException;

    /**
     * Release any resources associated.
     *
     * @throws KrbException e
     */
    void release() throws KrbException;
}
