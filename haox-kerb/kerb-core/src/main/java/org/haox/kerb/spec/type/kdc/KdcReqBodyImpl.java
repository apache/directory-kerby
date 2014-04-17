package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcReqBody;
import org.haox.kerb.spec.type.ticket.Tickets;

import java.util.Set;

public class KdcReqBodyImpl extends AbstractSequenceType implements KdcReqBody {
    private AuthorizationData authorizationData;

    @Override
    public KrbTime getFrom() throws KrbException {
        return getFieldAs(Tag.FROM, KrbTime.class);
    }

    @Override
    public void setFrom(KrbTime from) throws KrbException {
        setField(Tag.FROM, from);
    }

    @Override
    public KrbTime getTill() throws KrbException {
        return getFieldAs(Tag.TILL, KrbTime.class);
    }

    @Override
    public void setTill(KrbTime till) throws KrbException {
        setField(Tag.TILL, till);
    }

    @Override
    public KrbTime getRtime() throws KrbException {
        return getFieldAs(Tag.RTIME, KrbTime.class);
    }

    @Override
    public void setRtime(KrbTime rtime) throws KrbException {
        setField(Tag.RTIME, rtime);
    }

    @Override
    public int getNonce() {
        return 0;
    }

    @Override
    public void setNonce(int nonce) {

    }

    @Override
    public Set<EncryptionType> getEtype() {
        return null;
    }

    @Override
    public void setEtype(Set<EncryptionType> etype) {

    }

    @Override
    public HostAddresses getAddresses() {
        return null;
    }

    @Override
    public void setAddresses(HostAddresses addresses) {

    }

    @Override
    public EncryptedData getEncryptedAuthorizationData() throws KrbException {
        return getFieldAs(Tag.ENC_AUTHORIZATION_DATA, EncryptedData.class);
    }

    @Override
    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) throws KrbException {
        setField(Tag.ENC_AUTHORIZATION_DATA, encAuthorizationData);
    }

    @Override
    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    @Override
    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }

    @Override
    public Tickets getAdditionalTickets() throws KrbException {
        return getFieldAs(Tag.ADDITIONAL_TICKETS, Tickets.class);
    }

    @Override
    public void setAdditionalTickets(Tickets additionalTickets) throws KrbException {
        setField(Tag.ADDITIONAL_TICKETS, additionalTickets);
    }

    @Override
    public KdcOptions getKdcOptions() throws KrbException {
        return getFieldAs(Tag.KDC_OPTIONS, KdcOptions.class);
    }

    @Override
    public void setKdcOptions(KdcOptions kdcOptions) throws KrbException {
        setField(Tag.KDC_OPTIONS, kdcOptions);
    }

    @Override
    public PrincipalName getSname() throws KrbException {
        return getFieldAs(Tag.SNAME, PrincipalName.class);
    }

    @Override
    public void setSname(PrincipalName sname) throws KrbException {
        setField(Tag.SNAME, sname);
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
    public String getRealm() throws KrbException {
        return getFieldAsString(Tag.REALM);
    }

    @Override
    public void setRealm(String realm) throws KrbException {
        setField(Tag.REALM, KrbTypes.makeString(realm));
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
