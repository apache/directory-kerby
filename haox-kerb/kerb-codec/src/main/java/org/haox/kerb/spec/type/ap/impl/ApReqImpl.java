package org.haox.kerb.spec.type.ap.impl;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.common.impl.AbstractMessage;
import org.haox.kerb.spec.type.ticket.Ticket;

public class ApReqImpl extends AbstractMessage implements ApReq {
    private Authenticator authenticator;

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }

    public ApReqImpl() throws KrbException {
        super(KrbMessageType.AP_REP);
    }

    public ApOptions getApOptions() throws KrbException {
        return getFieldAs(Tag.AP_OPTIONS, ApOptions.class);
    }

    public void setApOptions(ApOptions apOptions) throws KrbException {
        setField(Tag.AP_OPTIONS, apOptions);
    }

    public Ticket getTicket() throws KrbException {
        return getFieldAs(Tag.TICKET, Ticket.class);
    }

    public void setTicket(Ticket ticket) throws KrbException {
        setField(Tag.TICKET, ticket);
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public EncryptedData getEncryptedAuthenticator() throws KrbException {
        return getFieldAs(Tag.AUTHENTICATOR, EncryptedData.class);
    }

    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) throws KrbException {
        setField(Tag.AUTHENTICATOR, encryptedAuthenticator);
    }
}
