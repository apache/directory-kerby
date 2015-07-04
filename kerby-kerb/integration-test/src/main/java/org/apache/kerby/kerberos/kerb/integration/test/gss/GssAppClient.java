package org.apache.kerby.kerberos.kerb.integration.test.gss;

import org.apache.kerby.kerberos.kerb.integration.test.AppClient;
import org.apache.kerby.kerberos.kerb.integration.test.AppUtil;
import org.apache.kerby.kerberos.kerb.integration.test.Transport;
import org.ietf.jgss.*;

public class GssAppClient extends AppClient {
    private String clientPrincipal;
    private String serverPrincipal;
    private GSSManager manager;

    @Override
    protected void usage(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: GssAppClient <server-host> <server-port> "
                    + "<client-principal> <server-principal> ");
            System.exit(-1);
        }
    }

    public GssAppClient(String[] args) throws Exception {
        super(args);

        clientPrincipal = args[2];
        serverPrincipal = args[3];
        this.manager = GSSManager.getInstance();
    }

    @Override
    protected void withConnection(Transport.Connection conn) throws Exception {
        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

        GSSName serverName = manager.createName(serverPrincipal,
                GSSName.NT_USER_NAME);
        Oid oid = new Oid(AppUtil.JGSS_KERBEROS_OID);
        GSSName clientName = manager.createName(clientPrincipal,
                GSSName.NT_USER_NAME);
        GSSCredential myCred = manager.createCredential(clientName,
                GSSCredential.DEFAULT_LIFETIME, oid, GSSCredential.INITIATE_ONLY);
        GSSContext context = manager.createContext(serverName,
                krb5Oid, myCred, GSSContext.DEFAULT_LIFETIME);
        context.requestMutualAuth(true);
        context.requestConf(true);
        context.requestInteg(true);

        byte[] token = new byte[0];
        while (!context.isEstablished()) {
            token = context.initSecContext(token, 0, token.length);
            if (token != null) {
                conn.sendToken(token);
            }
            if (!context.isEstablished()) {
                token = conn.recvToken();
            }
        }

        System.out.println("Context Established! ");
        System.out.println("Client is " + context.getSrcName());
        System.out.println("Server is " + context.getTargName());

        if (context.getMutualAuthState()) {
            System.out.println("Mutual authentication took place!");
        }

        byte[] messageBytes = "Hello There!\0".getBytes();
        MessageProp prop =  new MessageProp(0, true);
        token = context.wrap(messageBytes, 0, messageBytes.length, prop);
        System.out.println("Will send wrap token of size " + token.length);
        conn.sendToken(token);

        token = conn.recvToken();
        context.verifyMIC(token, 0, token.length,
                messageBytes, 0, messageBytes.length, prop);
        setTestOK(true);

        System.out.println("Verified received MIC for message.");
        context.dispose();
    }

    public static void main(String[] args) throws Exception  {
        new GssAppClient(args).run();
    }
}
