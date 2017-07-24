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

import org.apache.kerby.kerberos.kerb.server.LoginTestBase;
import org.apache.kerby.util.NetworkUtil;
import org.junit.Assert;
import org.junit.Before;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;

public abstract class AppTest extends LoginTestBase {
    private static final Logger LOG = LoggerFactory.getLogger(AppTest.class);
    private int serverPort;
    protected AppServer appServer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        serverPort = NetworkUtil.getServerPort();

        setupAppServer();
    }

    protected int getServerPort() {
        return serverPort;
    }

    protected void setupAppServer() throws Exception {
        Subject subject = loginServiceUsingKeytab();
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    appServer = createAppServer();
                    appServer.start();
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }

                return null;
            }
        });
    }

    protected abstract AppServer createAppServer() throws Exception;

    protected void runAppClient(final AppClient appClient) throws Exception {
        Subject subject = loginClientUsingTicketCache();
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    appClient.run();
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }
                return null;
            }
        });

        Assert.assertTrue("Client successfully connected and authenticated to server",
                appClient.isTestOK());
    }

}
