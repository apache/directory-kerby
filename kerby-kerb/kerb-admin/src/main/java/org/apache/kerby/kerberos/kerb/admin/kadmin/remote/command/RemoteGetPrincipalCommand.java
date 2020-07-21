package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

public class RemoteGetPrincipalCommand extends RemoteCommand {
    private static final String USAGE = "Usage: getprinc principalName\n"
            + "\tExample:\n"
            + "\t\tgetprinc hello@TEST.COM\n";
    
    public RemoteGetPrincipalCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipalName = items[items.length - 1];
        KrbIdentity identity = null;
        try {
            identity = adminClient.requestGetPrincipal(clientPrincipalName);
        } catch (KrbException e) {
            System.err.println("Failed to get principal: " + clientPrincipalName + ". " + e.toString());
        }
        if (identity == null) {
            return;
        } else {
            System.out.println("Principal is listed:");
            System.out.println(
                    "Principal: " + identity.getPrincipalName() + "\n"
                            + "Expiration date: " + identity.getExpireTime() + "\n"
                            + "Created time: " + identity.getCreatedTime() + "\n"
                            + "KDC flags: " + identity.getKdcFlags() + "\n"
                            + "Key version: " + identity.getKeyVersion() + "\n"
                            + "Number of keys: " + identity.getKeys().size()
            );
            
            for (EncryptionType keyType: identity.getKeys().keySet()) {
                System.out.println("key: " + keyType);
            }
        }
    }
}
