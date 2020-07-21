package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

import java.io.File;
import java.util.List;

public class RemoteKeytabAddCommand extends RemoteCommand {
    private static final String USAGE = "Usage: ktadd [-k[eytab] keytab] "
            + "[principal | -glob princ-exp] [...]\n"
            + "\tExample:\n"
            + "\t\tktadd hello@TEST.COM -k /keytab/location\n";
    private static final String DEFAULT_KEYTAB_FILE_LOCATION = "/etc/krb5.keytab";
    
    public RemoteKeytabAddCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");
        
        if (items.length < 2) {
            System.err.println(USAGE);
            return;
        }
        
        String principal = null;
        String keytabFileLocation = null;
        boolean glob = false;
        
        int index = 1;
        while (index < items.length) {
            String command = items[index];
            if (command.equals("-k")) {
                index++;
                if (index >= items.length) {
                    System.err.println(USAGE);
                    return;
                }
                keytabFileLocation = items[index].trim();
            } else if (command.equals("-glob")) {
                glob = true;
            } else if (!command.startsWith("-")) {
                principal = command;
            }
            index++;
        }
        
        if (keytabFileLocation == null) {
            keytabFileLocation = DEFAULT_KEYTAB_FILE_LOCATION;
        }
        File keytabFile = new File(keytabFileLocation);
        
        if (principal == null) {
            System.out.println((glob ? "princ-exp" : "principal") + " not specified!");
            System.err.println(USAGE);
            return;
        }
        
        try {
            if (glob) {
                List<String> principals = adminClient.requestGetprincsWithExp(principal);
                adminClient.requestExportKeytab(keytabFile, principals);
            } else {
                adminClient.requestExportKeytab(keytabFile, principal);
            }
            System.out.println("Export Keytab to " + keytabFileLocation);
        } catch (KrbException e) {
            System.err.println("Principal \"" + principal + "\" fail to add entry to keytab. " 
                    + e.toString());
        }
    }
}
