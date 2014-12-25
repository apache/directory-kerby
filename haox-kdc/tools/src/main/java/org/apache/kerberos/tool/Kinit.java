package org.apache.kerberos.tool;

import org.apache.kerberos.kerb.client.KrbClient;

/**
 * kinit like tool
 */
public class Kinit {

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) {
            System.err.println(
                    "Usage: " + Kinit.class.getSimpleName() +
                            " <kdcHost> <kdcPort>");
            return;
        }

        final String host = args[0];
        final Integer port = Integer.parseInt(args[1]);
        KrbClient krbClnt = new KrbClient(host, port.shortValue());
    }

}
