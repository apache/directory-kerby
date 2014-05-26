package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class KerberosTicket {
    private String serverPrincipalName;
    private String serverRealm;
    private Ticket ticket;

    public KerberosTicket(Ticket ticket, ApOptions apOptions, KerberosKey[] keys)
            throws KrbException, IOException {
        this.ticket = ticket;

        EncryptionType etype = ticket.getEncryptedEncPart().getEType();
        byte[] crypt = ticket.getEncryptedEncPart().getCipher();

        byte[] decrypted = null;
        try {
            decrypted = KerberosEncData.decrypt(crypt, etype);
        } catch(GeneralSecurityException e) {
            throw new IOException("kerberos.decrypt.fail", e);
        }

        try {
            EncTicketPart encPart = KrbCodec.decode(decrypted, EncTicketPart.class);
            ticket.setEncPart(encPart);
        } catch (KrbException e) {
            e.printStackTrace();
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
