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
package org.apache.kerby.kerberos.kerb.integration.test;

import java.io.File;

import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppClient;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppServer;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssJAASAppClient;
import org.junit.Test;

public class GssAppTest extends AppTest {

    @Override
    protected AppServer createAppServer() throws Exception {
        return new GssAppServer(new String[] {
            String.valueOf(getServerPort()),
            getServerPrincipal()
        });
    }

    @Test
    public void test() throws Exception {
        runAppClient(createAppClient());
    }

    @Test
    public void testJAAS() throws Exception {
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }

        try {
            System.setProperty("java.security.auth.login.config", basedir + "/target/test-classes/kerberos.jaas");
            runAppClient(createAppJAASClient());
        } finally {
            System.clearProperty("java.security.auth.login.config");
        }
    }

    private AppClient createAppClient() throws Exception {
        return new GssAppClient(new String[] {
            getHostname(),
            String.valueOf(getServerPort()),
                getClientPrincipal(),
                getServerPrincipal()
        });
    }

    private AppClient createAppJAASClient() throws Exception {
        return new GssJAASAppClient(new String[] {
            getHostname(),
            String.valueOf(getServerPort()),
            getServerPrincipal(),
            "drankye"
        }, new NamePasswordCallbackHandler(super.getClientPrincipalName(), super.getClientPassword()));
    }
}