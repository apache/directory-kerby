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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl;

import org.apache.kerby.kerberos.kerb.admin.AuthUtil;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerHandler;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslServer;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;

public class DefaultAdminServerHandler extends AdminServerHandler implements Runnable {
    private static Logger logger = LoggerFactory.getLogger(DefaultAdminServerHandler.class);
    private final KrbTransport transport;
    private static boolean sasl = false;
    private AdminServerContext adminServerContext;

    public DefaultAdminServerHandler(AdminServerContext adminServerContext, KrbTransport transport) {
        super(adminServerContext);
        this.transport  = transport;
        this.adminServerContext = adminServerContext;
    }

    @Override
    public void run() {
        while (true) {
            try {
                if (!sasl) {
                    logger.info("Doing the sasl negotiation !!!");
                    try {
                        saslNegotiation();
                    } catch (Exception e) {
                        logger.error("With exception when sasl negotiation." + e);
                    }
                } else {
                    ByteBuffer message = transport.receiveMessage();
                    if (message == null) {
                        logger.debug("No valid request recved. Disconnect actively");
                        transport.release();
                        break;
                    }
                    handleMessage(message);
                }
            } catch (IOException e) {
                transport.release();
                logger.debug("Transport or decoding error occurred, "
                        + "disconnecting abnormally", e);
                break;
            }
        }
    }

    protected void handleMessage(ByteBuffer message) {
        InetAddress clientAddress = transport.getRemoteAddress();

        try {
            ByteBuffer adminResponse = handleMessage(message, clientAddress);
            transport.sendMessage(adminResponse);
        } catch (Exception e) {
            transport.release();
            logger.error("Error occured while processing request:", e);
        }
    }

    private void saslNegotiation() throws Exception {

        File keytabFile = new File(adminServerContext.getConfig().getKeyTabFile());
        String principal = adminServerContext.getConfig().getProtocol() + "/"
            + adminServerContext.getConfig().getAdminHost();

        Subject subject = AuthUtil.loginUsingKeytab(principal, keytabFile);
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    ByteBuffer message = null;
                    try {
                        message = transport.receiveMessage();
                    } catch (SocketTimeoutException e) {
                        // ignore time out
                        return null;
                    }

                    Map<String, Object> props = new HashMap<String, Object>();
                    props.put(Sasl.QOP, "auth-conf");
                    props.put(Sasl.SERVER_AUTH, "true");

                    String protocol = adminServerContext.getConfig().getProtocol();
                    String serverName = adminServerContext.getConfig().getServerName();
                    CallbackHandler callbackHandler = new SaslGssCallbackHandler();
                    SaslServer ss = Sasl.createSaslServer("GSSAPI",
                        protocol, serverName, props, callbackHandler);

                    if (ss == null) {
                        throw new Exception("Unable to find server implementation for: GSSAPI");
                    }

                    while (!ss.isComplete()) {
                        int scComplete = message.getInt();
                        if (scComplete == 0) {
                            logger.info("sasl negotiation success!!!");
                            sasl = true;
                            break;
                        }
                        sendMessage(message, ss);
                        if (!ss.isComplete()) {
                            logger.info("Waiting receive message");
                            message = transport.receiveMessage();
                        }
                    }
                } catch (Exception e) {
                    logger.error("With exception when sasl negotiation. " + e);
                }
                return null;
            }
        });

    }

    private void sendMessage(ByteBuffer message, SaslServer ss) throws IOException {

        byte[] arr = new byte[message.remaining()];
        message.get(arr);
        byte[] challenge = ss.evaluateResponse(arr);

        // 4 is the head to go through network
        ByteBuffer buffer = ByteBuffer.allocate(challenge.length + 8);
        buffer.putInt(challenge.length + 4);
        int ssComplete = ss.isComplete() ? 0 : 1;
        buffer.putInt(ssComplete);
        buffer.put(challenge);
        buffer.flip();
        transport.sendMessage(buffer);
        logger.info("Send message to admin client.");
    }

    private static class SaslGssCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws
            UnsupportedCallbackException {
            AuthorizeCallback ac = null;
            for (Callback callback : callbacks) {
                if (callback instanceof AuthorizeCallback) {
                    ac = (AuthorizeCallback) callback;
                } else {
                    throw new UnsupportedCallbackException(callback,
                        "Unrecognized SASL GSSAPI Callback");
                }
            }
            if (ac != null) {
                String authid = ac.getAuthenticationID();
                String authzid = ac.getAuthorizationID();
                if (authid.equals(authzid)) {
                    ac.setAuthorized(true);
                } else {
                    ac.setAuthorized(false);
                }
                if (ac.isAuthorized()) {
                    ac.setAuthorizedID(authzid);
                }
            }
        }
    }
}