package org.apache.kerberos.kerb.codec.kerberos;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerberos.kerb.spec.common.AuthorizationData;
import org.apache.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.KeyUsage;
import org.apache.kerberos.kerb.spec.ticket.EncTicketPart;
import org.apache.kerberos.kerb.spec.ticket.Ticket;

import java.util.Arrays;

public class KerberosTicket {
    private String serverPrincipalName;
    private String serverRealm;
    private Ticket ticket;

    public KerberosTicket(Ticket ticket, ApOptions apOptions, EncryptionKey key)
            throws Exception {
        this.ticket = ticket;

        byte[] decrypted = EncryptionHandler.decrypt(
                ticket.getEncryptedEncPart(), key, KeyUsage.KDC_REP_TICKET);

        EncTicketPart encPart = KrbCodec.decode(decrypted, EncTicketPart.class);
        ticket.setEncPart(encPart);

        /**
         * Also test encryption by the way
         */
        EncryptedData encrypted = EncryptionHandler.encrypt(
                decrypted, key, KeyUsage.KDC_REP_TICKET);

        byte[] decrypted2 = EncryptionHandler.decrypt(
                encrypted, key, KeyUsage.KDC_REP_TICKET);
        if (!Arrays.equals(decrypted, decrypted2)) {
            throw new KrbException("Encryption checking failed after decryption");
        }
    }

    public String getUserPrincipalName() throws KrbException {
        return ticket.getEncPart().getCname().getName();
    }

    public String getUserRealm() throws KrbException {
        return ticket.getEncPart().getCrealm();
    }

    public String getServerPrincipalName() throws KrbException {
        return ticket.getSname().getName();
    }

    public String getServerRealm() throws KrbException {
        return ticket.getRealm();
    }

    public AuthorizationData getAuthorizationData() throws KrbException {
        return ticket.getEncPart().getAuthorizationData();
    }

    public Ticket getTicket() {
        return ticket;
    }
}
