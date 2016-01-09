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
package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;

import java.io.File;
import java.util.List;

/**
 * Server side admin facilities for remote, similar to MIT kadmind service.
 * It uses GSSAPI and XDR to communicate with remote client/kadmin to receive
 * and perform the requested operations. In this server side, it simply leverages
 * LocalKadmin to perform the real work.
 *
 * TO BE IMPLEMENTED.
 */
public class AdminServer implements Kadmin {
    //private LocalKadmin localKadmin;

    @Override
    public String getKadminPrincipal() {
        return null;
    }

    @Override
    public void addPrincipal(String principal) throws KrbException {

    }

    @Override
    public void addPrincipal(String principal,
                             KOptions kOptions) throws KrbException {

    }

    @Override
    public void addPrincipal(String principal,
                             String password) throws KrbException {

    }

    @Override
    public void addPrincipal(String principal, String password,
                             KOptions kOptions) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile,
                             String principal) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile,
                             List<String> principals) throws KrbException {

    }

    @Override
    public void exportKeytab(File keytabFile) throws KrbException {

    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile,
                                      String principal) throws KrbException {

    }

    @Override
    public void removeKeytabEntriesOf(File keytabFile, String principal,
                                      int kvno) throws KrbException {

    }

    @Override
    public void removeOldKeytabEntriesOf(File keytabFile,
                                         String principal) throws KrbException {

    }

    @Override
    public void deletePrincipal(String principal) throws KrbException {

    }

    @Override
    public void modifyPrincipal(String principal,
                                KOptions kOptions) throws KrbException {

    }

    @Override
    public void renamePrincipal(String oldPrincipalName,
                                String newPrincipalName) throws KrbException {

    }

    @Override
    public List<String> getPrincipals() throws KrbException {
        return null;
    }

    @Override
    public List<String> getPrincipals(String globString) throws KrbException {
        return null;
    }

    @Override
    public void changePassword(String principal,
                               String newPassword) throws KrbException {

    }

    @Override
    public void updateKeys(String principal) throws KrbException {

    }

    @Override
    public void release() throws KrbException {

    }
}
