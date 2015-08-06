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
package org.apache.kerby.kerberos.tool.kadmin.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.Kadmin;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.util.Map;

public class GetPrincipalCommand extends KadminCommand {
    private static final String USAGE = "Usage: getprinc principalName\n"
            + "such as, getprinc hello@TEST.COM";

    public GetPrincipalCommand(Kadmin kadmin) {
        super(kadmin);
    }

    @Override
    public void execute(String input) {
        String[] commands = input.split(" ");

        if (commands.length != 2) {
            System.err.println(USAGE);
            return;
        }

        String princName = commands[commands.length - 1];
        KrbIdentity identity = null;
        try {
            identity = getKadmin().getPrincipal(princName);
        } catch (KrbException e) {
            System.err.println("Fail to get principal: " + princName + ". " + e.getMessage());
        }

        if (identity == null) {
            System.err.println(princName + " doesn't exist\n");
            System.err.println(USAGE);
            return;
        }

        Map<EncryptionType, EncryptionKey> key = identity.getKeys();

        System.out.println(
                "Principal: " + identity.getPrincipalName() + "\n"
                        + "Expiration data: " + identity.getExpireTime() + "\n"
                        + "Created time: "
                        + identity.getCreatedTime() + "\n"
                        + "KDC flags: " + identity.getKdcFlags() + "\n"
                        + "Key version: " + identity.getKeyVersion() + "\n"
                        + "Number of keys: " + key.size()
        );

        for (EncryptionType keyType : key.keySet()) {
            System.out.println("key: " + keyType);
        }
    }
}
