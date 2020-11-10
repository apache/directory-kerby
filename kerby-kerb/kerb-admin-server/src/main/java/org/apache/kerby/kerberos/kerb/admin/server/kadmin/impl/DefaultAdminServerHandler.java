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
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.NegotiationStatus;
import org.apache.kerby.kerberos.kerb.admin.message.KadminCode;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerHandler;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.transport.KrbTcpTransport;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.xnio.sasl.SaslUtils;
import org.xnio.sasl.SaslWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

public class DefaultAdminServerHandler extends AdminServerHandler implements Runnable {
    private static Logger logger = LoggerFactory.getLogger(DefaultAdminServerHandler.class);
    private static final String MECHANISM = "GSSAPI";
    private final KrbTransport transport;
    private AdminServerContext adminServerContext;

    public DefaultAdminServerHandler(AdminServerContext adminServerContext, KrbTransport transport) {
        super(adminServerContext);
        this.transport  = transport;
        this.adminServerContext = adminServerContext;
    }

    @Override
    public void run() {
        try {
            doSaslHandshake();
        } catch (Exception e) {
            logger.error("With exception when SASL negotiation." + e);
            return;
        }
        do {
            try {
                ByteBuffer message = transport.receiveMessage();
                if (message == null) {
                    logger.debug("No valid request recved. Disconnect actively");
                    transport.release();
                    break;
                }
                // unwrap SASL message
                ByteBuffer unwrapMessage = ByteBuffer.wrap(getSaslServerWrapper().unwrap(message));
                handleMessage(unwrapMessage);
            } catch (IOException e) {
                transport.release();
                logger.debug("Transport or decoding error occurred, "
                        + "disconnecting abnormally", e);
                break;
            }
        } while (!((KrbTcpTransport) transport).isClosed());
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

    private void doSaslHandshake() throws Exception {
        File keytabFile = new File(adminServerContext.getConfig().getKeyTabFile());
        String principal = adminServerContext.getConfig().getProtocol() + "/"
            + adminServerContext.getConfig().getAdminHost();
        String fixedPrincipal = AdminServerUtil.fixPrincipal(principal, adminServerContext.getAdminServerSetting());
        String adminPrincipal = KrbUtil.makeKadminPrincipal(
                adminServerContext.getAdminServerSetting().getKdcRealm()).getName();
        
        Subject subject = AuthUtil.loginUsingKeytab(fixedPrincipal, keytabFile);
        Subject.doAs(subject, (PrivilegedExceptionAction<Object>) () -> {
            boolean success = false;
            try {
                ByteBuffer message;
                try {
                    message = transport.receiveMessage();
                } catch (SocketTimeoutException ignore) {
                    // Ignore time out, wake up to see if should continue to run.
                    // When client create a new tpc transport, socket always timeout,
                    // because the first connection will not send message to the server.
                    // SASL handshake is not performed until the connection is established.
                    return null;
                }

                Map<String, Object> props = new HashMap<>();
                props.put(Sasl.QOP, "auth-conf");
                props.put(Sasl.SERVER_AUTH, "true");
                String protocol = adminServerContext.getConfig().getProtocol();
                String serverName = adminServerContext.getConfig().getServerName();
                CallbackHandler callbackHandler = new SaslGssCallbackHandler(adminPrincipal);
                SaslServer saslServer = Sasl.createSaslServer(MECHANISM, protocol,
                        serverName, props, callbackHandler);

                if (saslServer == null) {
                    throw new Exception("Unable to find server implementation for: GSSAPI");
                }

                setSaslServerWrapper(SaslWrapper.create(saslServer));

                while (!saslServer.isComplete()) {
                    int scComplete = message.getInt();
                    if (scComplete == NegotiationStatus.SUCCESS.getValue()) {
                        logger.info("Sasl Client completed");
                    }

                    byte[] challenge = null;
                    try {
                        challenge = SaslUtils.evaluateResponse(saslServer, message);
                    } catch (SaslException e) {
                        throw new Exception("Sasl server evaluate challenge failed. " + e);
                    }

                    if (!saslServer.isComplete()) {
                        // Send message to client only when SASL server is not complete
                        sendMessage(challenge, saslServer);

                        logger.info("Waiting receive message");
                        message = transport.receiveMessage();
                    }
                }
                success = true;
            } finally {
                if (!success) {
                    transport.release();
                }
            }
            return null;
        });
    }

    private void sendMessage(byte[] challenge, SaslServer saslServer) throws IOException {
        NegotiationStatus status = saslServer.isComplete()
                ? NegotiationStatus.SUCCESS : NegotiationStatus.CONTINUE;
        ByteBuffer buffer = KadminCode.encodeSaslMessage(challenge, status);
        try {
            transport.sendMessage(buffer);
            logger.info("Send message to admin client.");
        } catch (SaslException e) {
            logger.error("Failed to send message to client. " + e.toString());
        }
    }

    private static class SaslGssCallbackHandler implements CallbackHandler {

        private final String adminPrincipal;

        SaslGssCallbackHandler(String principal) {
            this.adminPrincipal = principal;
        }
        
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
                if (authid.equals(authzid) && authid.equals(adminPrincipal)) {
                    ac.setAuthorized(true);
                } else {
                    logger.warn("Client try to login using principal " + authid);
                    ac.setAuthorized(false);
                }
                if (ac.isAuthorized()) {
                    ac.setAuthorizedID(authzid);
                }
            }
        }
    }
}