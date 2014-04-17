package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.TicketFlags;

public class EncTicketPartImpl extends AbstractSequenceType implements EncTicketPart {
    @Override
    public TicketFlags getFlags() throws KrbException {
        return getFieldAs(Tag.FLAGS, TicketFlags.class);
    }

    @Override
    public void setFlags(TicketFlags flags) throws KrbException {
        setField(Tag.FLAGS, flags);
    }

    @Override
    public EncryptionKey getKey() throws KrbException {
        return getFieldAs(Tag.KEY, EncryptionKey.class);
    }

    @Override
    public void setKey(EncryptionKey key) throws KrbException {
        setField(Tag.KEY, key);
    }

    @Override
    public String getCrealm() throws KrbException {
        return getFieldAsString(Tag.CREALM);
    }

    @Override
    public void setCrealm(String crealm) throws KrbException {
        setField(Tag.CREALM, KrbTypes.makeString(crealm));
    }

    @Override
    public PrincipalName getCname() throws KrbException {
        return getFieldAs(Tag.CNAME, PrincipalName.class);
    }

    @Override
    public void setCname(PrincipalName cname) throws KrbException {
        setField(Tag.CNAME, cname);
    }

    @Override
    public TransitedEncoding getTransited() throws KrbException {
        return getFieldAs(Tag.TRANSITED, TransitedEncoding.class);
    }

    @Override
    public void setTransited(TransitedEncoding transited) throws KrbException {
        setField(Tag.TRANSITED, transited);
    }

    @Override
    public KrbTime getAuthTime() throws KrbException {
        return getFieldAs(Tag.AUTHTIME, KrbTime.class);
    }

    @Override
    public void setAuthTime(KrbTime authTime) throws KrbException {
        setField(Tag.AUTHTIME, authTime);
    }

    @Override
    public KrbTime getStartTime() throws KrbException {
        return getFieldAs(Tag.STARTTIME, KrbTime.class);
    }

    @Override
    public void setStartTime(KrbTime startTime) throws KrbException {
        setField(Tag.STARTTIME, startTime);
    }

    @Override
    public KrbTime getEndTime() throws KrbException {
        return getFieldAs(Tag.ENDTIME, KrbTime.class);
    }

    @Override
    public void setEndTime(KrbTime endTime) throws KrbException {
        setField(Tag.ENDTIME, endTime);
    }

    @Override
    public KrbTime getRenewtill() throws KrbException {
        return getFieldAs(Tag.RENEW_TILL, KrbTime.class);
    }

    @Override
    public void setRenewtill(KrbTime renewtill) throws KrbException {
        setField(Tag.RENEW_TILL, renewtill);
    }

    @Override
    public HostAddresses getClientAddresses() throws KrbException {
        return getFieldAs(Tag.CADDR, HostAddresses.class);
    }

    @Override
    public void setClientAddresses(HostAddresses clientAddresses) throws KrbException {
        setField(Tag.CADDR, clientAddresses);
    }

    @Override
    public AuthorizationData getAuthorizationData() throws KrbException {
        return getFieldAs(Tag.AUTHORIZATION_DATA, AuthorizationData.class);
    }

    @Override
    public void setAuthorizationData(AuthorizationData authorizationData) throws KrbException {
        setField(Tag.AUTHORIZATION_DATA, authorizationData);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
