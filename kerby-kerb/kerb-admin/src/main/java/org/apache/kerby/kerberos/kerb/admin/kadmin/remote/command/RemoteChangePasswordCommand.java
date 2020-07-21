package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

public class RemoteChangePasswordCommand extends RemoteCommand {
    private static final String USAGE = "Usage: change_password [-pw newPassword] principal";

    public RemoteChangePasswordCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");

        if (items.length < 4) {
            System.err.println(USAGE);
            return;
        }

        String clientPrincipal = items[items.length - 1];

        if (items[1].startsWith("-pw")) {
            String newPassword = items[2];
            adminClient.requestChangePassword(clientPrincipal, newPassword);
            System.out.println("Password updated successfully.");
        } else {
            System.err.println("change_password command error.");
            System.err.println(USAGE);
        }
    }
}
