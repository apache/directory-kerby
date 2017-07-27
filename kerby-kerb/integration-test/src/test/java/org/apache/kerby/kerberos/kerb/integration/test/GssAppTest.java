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

import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.apache.kerby.kerberos.kerb.client.JaasKrbUtil;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppClient;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppServer;
import org.apache.kerby.util.NetworkUtil;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GssAppTest extends AppTest {

    private static final Logger LOG = LoggerFactory.getLogger(GssAppTest.class);

    private int serverPort2;
    private int serverPort3;
    private AppServer appServer2;
    private AppServer appServer3;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        serverPort2 = NetworkUtil.getServerPort();
        serverPort3 = NetworkUtil.getServerPort();

        setupAppServer2();
        setupAppServer3();
    }

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
    public void testWithoutInitialCredential() throws Exception {
        AppClient appClient = createAppClient();
        ((GssAppClient) appClient).setCreateContextWithCred(false);
        runAppClient(appClient);
    }

    @Test
    public void testServerWithoutInitialCredential() throws Exception {
        AppClient appClient =
            new GssAppClient(new String[] {
                                           getHostname(),
                                           String.valueOf(serverPort2),
                                           getClientPrincipal(),
                                           getServerPrincipal()
            });
        runAppClient(appClient);
    }

    // Here the server is using a password to get a TGT, not a keytab
    @Test
    public void testServerUsingPassword() throws Exception {
        AppClient appClient =
            new GssAppClient(new String[] {
                                           getHostname(),
                                           String.valueOf(serverPort3),
                                           getClientPrincipal(),
                                           getServerPrincipal()
            });
        runAppClient(appClient);
    }

    private AppClient createAppClient() throws Exception {
        return new GssAppClient(new String[] {
            getHostname(),
            String.valueOf(getServerPort()),
                getClientPrincipal(),
                getServerPrincipal()
        });
    }

    private void setupAppServer2() throws Exception {
        Subject subject = loginServiceUsingKeytab();
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    appServer2 =
                        new GssAppServer(new String[] {
                                                       String.valueOf(serverPort2),
                                                       getServerPrincipal()
                        });
                    ((GssAppServer) appServer2).setCreateContextWithCred(false);
                    appServer2.start();
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }

                return null;
            }
        });
    }

    private void setupAppServer3() throws Exception {
        Subject subject = JaasKrbUtil.loginUsingPassword(getServerPrincipal(), getServerPassword());
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    appServer3 =
                        new GssAppServer(new String[] {
                                                       String.valueOf(serverPort3),
                                                       getServerPrincipal()
                        });
                    appServer3.start();
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }

                return null;
            }
        });
    }

}