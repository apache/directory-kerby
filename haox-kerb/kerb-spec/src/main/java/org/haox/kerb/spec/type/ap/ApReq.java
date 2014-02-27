package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.ticket.Ticket;

/**
 AP-REQ          ::= [APPLICATION 14] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (14),
 ap-options      [2] APOptions,
 ticket          [3] Ticket,
 authenticator   [4] EncryptedData -- Authenticator
 }
 */
public abstract class ApReq extends KrbMessage {
    private ApOptions apOptions;
    private Ticket ticket;
    private Authenticator authenticator;
    private EncryptedData encryptedAuthenticator;

    public ApReq() {
        super(KrbMessageType.AP_REP);
    }

    public ApOptions getApOptions() {
        return apOptions;
    }

    public void setApOptions(ApOptions apOptions) {
        this.apOptions = apOptions;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public EncryptedData getEncryptedAuthenticator() {
        return encryptedAuthenticator;
    }

    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) {
        this.encryptedAuthenticator = encryptedAuthenticator;
    }
}
