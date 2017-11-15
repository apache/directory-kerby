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
package org.apache.hadoop.has.common;

import java.io.File;
import java.util.List;

/**
 * Server side admin facilities from remote, similar to MIT kadmin remote mode.
 */
public interface HasAdmin {

    /**
     * Get the hadmin principal name.
     *
     * @return The hadmin principal name.
     */
    String getHadminPrincipal();

    /**
     * Add principal to backend.
     *
     * @param principal The principal to be added into backend
     * @throws HasException e
     */
    void addPrincipal(String principal) throws HasException;

    /**
     * Add principal to backend.
     *
     * @param principal The principal to be added into backend
     * @param password  The password to create encryption key
     * @throws HasException e
     */
    void addPrincipal(String principal, String password) throws HasException;

    /**
     * Export all the keys of the specified principal into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principal The principal name
     * @throws HasException e
     */
    void exportKeytab(File keytabFile, String principal) throws HasException;

    /**
     * Export all the keys of the specified principals into the specified keytab
     * file.
     *
     * @param keytabFile The keytab file
     * @param principals The principal names
     * @throws HasException e
     */
    void exportKeytab(File keytabFile, List<String> principals) throws HasException;

    /**
     * Delete the principal in backend.
     *
     * @param principal The principal to be deleted from backend
     * @throws HasException e
     */
    void deletePrincipal(String principal) throws HasException;

    /**
     * Rename the principal.
     *
     * @param oldPrincipalName The original principal name
     * @param newPrincipalName The new principal name
     * @throws HasException e
     */
    void renamePrincipal(String oldPrincipalName,
                         String newPrincipalName) throws HasException;

    /**
     * Get all the principal names from backend.
     *
     * @return principal list
     * @throws HasException e
     */
    List<String> getPrincipals() throws HasException;

    /**
     * Get all the principal names that meets the pattern
     *
     * @param globString The glob string for matching
     * @return Principal names
     * @throws HasException e
     */
    List<String> getPrincipals(String globString) throws HasException;

    /**
     * Change the password of specified principal.
     *
     * @param principal The principal to be updated password
     * @param newPassword The new password
     * @throws HasException e
     */
//    void changePassword(String principal, String newPassword) throws HasException;

    /**
     * Update the random keys of specified principal.
     *
     * @param principal The principal to be updated keys
     * @throws HasException e
     */
//    void updateKeys(String principal) throws HasException;

    /**
     * Release any resources associated.
     *
     * @throws HasException e
     */
//    void release() throws HasException;

    String addPrincByRole(String host, String role) throws HasException;

    File getKeytabByHostAndRole(String host, String role) throws HasException;

    int size() throws HasException;

    void setEnableOfConf(String isEnable) throws HasException;
}
