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
package org.apache.kerby.kerberos.kerb.integration.test.gss;

import org.apache.kerby.kerberos.kerb.integration.test.AppClient;
import org.apache.kerby.kerberos.kerb.integration.test.Transport;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;

/**
 * A variant of GssAppClient that uses JAAS to get a tgt.
 */
public class GssJAASAppClient extends AppClient {
    private String serverPrincipal;
    private GSSManager manager;
    private String contextName;
    private CallbackHandler callbackHandler;

    public GssJAASAppClient(String[] args, CallbackHandler callbackHandler) throws Exception {
        super(args);

        serverPrincipal = args[2];
        contextName = args[3];
        this.callbackHandler = callbackHandler;
        this.manager = GSSManager.getInstance();
    }

    @Override
    protected void withConnection(final Transport.Connection conn) throws Exception {
        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

        GSSName serverName = manager.createName(serverPrincipal, GSSName.NT_USER_NAME);

        LoginContext lc = new LoginContext(contextName, null, callbackHandler, null);
        lc.login();
        Subject subject = lc.getSubject();

        GSSContext context = manager.createContext(serverName,
                                                   krb5Oid, null, GSSContext.DEFAULT_LIFETIME);
        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);

        byte[] token = (byte[]) Subject.doAs(subject, new CreateServiceTicketAction(context, conn));

        //System.out.println("Context Established! ");
        //System.out.println("Client is " + context.getSrcName());
        //System.out.println("Server is " + context.getTargName());

        //if (context.getMutualAuthState()) {
            //System.out.println("Mutual authentication took place!");
        //}

        byte[] messageBytes = "Hello There!\0".getBytes(StandardCharsets.UTF_8);
        MessageProp prop =  new MessageProp(0, true);
        token = context.wrap(messageBytes, 0, messageBytes.length, prop);
        //System.out.println("Will send wrap token of size " + token.length);
        conn.sendToken(token);

        token = conn.recvToken();
        context.verifyMIC(token, 0, token.length,
                messageBytes, 0, messageBytes.length, prop);
        setTestOK(true);

        //System.out.println("Verified received MIC for message.");
        context.dispose();
        lc.logout();
    }

    private static final class CreateServiceTicketAction implements PrivilegedExceptionAction<byte[]> {
        private final GSSContext context;
        private Transport.Connection conn;

        private CreateServiceTicketAction(GSSContext context, final Transport.Connection conn) {
            this.context = context;
            this.conn = conn;
        }

        public byte[] run() throws GSSException {
            byte[] token = new byte[0];
            while (!context.isEstablished()) {
                token = context.initSecContext(token, 0, token.length);
                try {
                    if (token != null) {
                        conn.sendToken(token);
                    }
                    if (!context.isEstablished()) {
                        token = conn.recvToken();
                    }
                } catch (IOException ex) {
                    throw new GSSException(GSSException.FAILURE);
                }
            }

            return token;
        }
    }
}
