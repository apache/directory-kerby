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

import org.apache.kerby.kerberos.kerb.integration.test.AppServer;
import org.apache.kerby.kerberos.kerb.integration.test.AppUtil;
import org.apache.kerby.kerberos.kerb.integration.test.Transport;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import java.nio.charset.Charset;

public class GssAppServer extends AppServer {
    private String serverPrincipal;
    private GSSManager manager;
    private GSSContext context;

    public GssAppServer(String[] args) throws Exception {
        super(args);
        if (args.length < 2) {
            usage(args);
        }
        this.serverPrincipal = args[1];

        this.manager = GSSManager.getInstance();
        GSSName gssService = manager.createName(
                serverPrincipal, GSSName.NT_USER_NAME);
        Oid oid = new Oid(AppUtil.JGSS_KERBEROS_OID);
        GSSCredential credentials = manager.createCredential(gssService,
                GSSCredential.DEFAULT_LIFETIME, oid, GSSCredential.ACCEPT_ONLY);
        this.context = manager.createContext(credentials);
    }

    public static void main(String[] args) throws Exception {
        new GssAppServer(args).run();
    }

    protected void usage(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: AppServer <ListenPort> <server-principal>");
            throw new RuntimeException("Usage: AppServer <ListenPort> <server-principal>");
        }
    }

    @Override
    protected void onConnection(Transport.Connection conn) throws Exception {
        byte[] token;

        System.out.print("Starting negotiating security context");
        while (!context.isEstablished()) {
            token = conn.recvToken();
            token = context.acceptSecContext(token, 0, token.length);
            if (token != null) {
                conn.sendToken(token);
            }
        }

        System.out.print("Context Established! ");
        System.out.println("Client is " + context.getSrcName());
        System.out.println("Server is " + context.getTargName());

        doWith(context, conn);

        context.dispose();
    }

    protected void doWith(GSSContext context,
                          Transport.Connection conn) throws Exception {
        if (context.getMutualAuthState()) {
            System.out.println("Mutual authentication took place!");
        }

        MessageProp prop = new MessageProp(0, false);
        byte[] token = conn.recvToken();
        byte[] bytes = context.unwrap(token, 0, token.length, prop);
        String str = new String(bytes, Charset.forName("UTF-8"));
        System.out.println("Received data \""
                + str + "\" of length " + str.length());

        System.out.println("Confidentiality applied: "
                + prop.getPrivacy());

        prop.setQOP(0);
        token = context.getMIC(bytes, 0, bytes.length, prop);
        System.out.println("Will send MIC token of size "
                + token.length);
        conn.sendToken(token);
    }
}
