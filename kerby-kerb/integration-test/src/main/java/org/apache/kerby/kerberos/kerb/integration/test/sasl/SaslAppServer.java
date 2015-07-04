package org.apache.kerby.kerberos.kerb.integration.test.sasl;

import org.apache.kerby.kerberos.kerb.integration.test.AppServer;
import org.apache.kerby.kerberos.kerb.integration.test.Transport;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SaslAppServer extends AppServer {
    private String mechanism;
    private String serviceProtocol;
    private String serverFqdn;

    @Override
    protected void usage(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: SaslAppServer "
                    + "<ListenPort> <service-protocol> <server-fqdn>");
            System.exit(-1);
        }
    }

    public SaslAppServer(String[] args) throws Exception {
        super(args);

        this.mechanism = "GSSAPI";
        this.serviceProtocol = args[1];
        this.serverFqdn = args[2];
    }

    @Override
    protected void onConnection(Transport.Connection conn) throws Exception {
        System.out.print("Starting negotiating security context");

        //mechanism, protocol, serverId, saslProperties, callback
        CallbackHandler callbackHandler = new SaslGssCallbackHandler();
        Map<String, Object> props = new HashMap<String, Object>();
        props.put(Sasl.QOP, "auth");

        SaslServer ss = Sasl.createSaslServer(mechanism,
                serviceProtocol, serverFqdn, props, callbackHandler);
        Transport.Message msg = conn.recvMessage();
        while (!ss.isComplete()) {
            try {
                byte[] respToken = ss.evaluateResponse(msg.body);
                if (ss.isComplete()) {
                    conn.sendMessage("OK", respToken);
                } else {
                    conn.sendMessage("CONT", respToken);
                    msg = conn.recvMessage();
                }

            } catch (SaslException e) {
                conn.sendMessage("ERR", null);
                ss.dispose();
                break;
            }
        }

        System.out.print("Context Established! ");

        doWith(ss, props, conn);

        ss.dispose();
    }

    protected void doWith(SaslServer ss, Map<String, Object> props,
                          Transport.Connection conn) throws IOException, Exception {
        byte[] token = conn.recvToken();
        String str = new String(token);
        System.out.println("Received data \""
                + str + "\" of length " + str.length());
    }

    public static class SaslGssCallbackHandler implements CallbackHandler {

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
                    System.out.println("SASL server GSSAPI callback: setting "
                            + "canonicalized client ID: " + authzid);
                    ac.setAuthorizedID(authzid);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new SaslAppServer(args).run();
    }
}
