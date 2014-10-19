package org.haox.kerb.client;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.haox.transport.Transport;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public abstract class KdcRequest {
    private KrbContext context;
    private Transport transport;

    private List<HostAddress> hostAddresses = new ArrayList<HostAddress>();
    private KdcOptions kdcOptions = new KdcOptions();
    private boolean preauthRequired = true;
    private List<EncryptionType> encryptionTypes;
    private EncryptionType chosenEncryptionType;
    private EncryptionKey clientKey;
    private int chosenNonce;

    public KdcRequest(KrbContext context) {
        this.context = context;
    }

    public void setTransport(Transport transport) {
        this.transport = transport;
    }

    public Transport getTransport() {
        return this.transport;
    }

    public abstract KdcReq makeKdcRequest() throws KrbException;

    protected KdcReqBody makeReqBody() throws KrbException {
        KdcReqBody body = new KdcReqBody();

        long startTime = System.currentTimeMillis();
        body.setFrom(new KerberosTime(startTime));

        PrincipalName cName = null;
        cName = getClientPrincipal();
        body.setCname(cName);

        body.setRealm(cName.getRealm());

        PrincipalName sName = getServerPrincipal();
        body.setSname(sName);

        body.setTill(new KerberosTime(startTime + getTicketValidTime()));

        int nonce = generateNonce();
        body.setNonce(nonce);
        setChosenNonce(nonce);

        body.setKdcOptions(getKdcOptions());

        HostAddresses addresses = getHostAddresses();
        if (addresses != null) {
            body.setAddresses(addresses);
        }

        List<EncryptionType> etypes = getEncryptionTypes();
        if (etypes.isEmpty()) {
            throw new KrbException("No encryption type is configured and available");
        }
        body.setEtypes(etypes);

        EncryptionType encryptionType = etypes.iterator().next();
        setChosenEncryptionType(encryptionType);

        return body;
    }

    public KdcOptions getKdcOptions() {
        return kdcOptions;
    }

    public HostAddresses getHostAddresses() {
        HostAddresses addresses = null;
        if (!hostAddresses.isEmpty()) {
            addresses = new HostAddresses();
            for(HostAddress ha : hostAddresses) {
                addresses.addElement(ha);
            }
        }
        return addresses;
    }

    public KrbContext getContext() {
        return context;
    }

    protected EncryptedData encodingAndEncryptWithClientKey(Asn1Type value, KeyUsage usage) throws KrbException {
        byte[] encodedData = value.encode();
        return EncryptionHandler.encrypt(encodedData, getClientKey(), usage);
    }

    public byte[] decryptWithClientKey(EncryptedData data, KeyUsage usage) throws KrbException {
        return EncryptionHandler.decrypt(data, getClientKey(), usage);
    }

    protected PaDataEntry makeTimeStampPaDataEntry() throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        long paTimestamp = System.currentTimeMillis();
        paTs.setPaTimestamp(new KerberosTime(paTimestamp));

        EncryptedData paDataValue = encodingAndEncryptWithClientKey(paTs, KeyUsage.AS_REQ_PA_ENC_TS);
        PaDataEntry tsPaEntry = new PaDataEntry();
        tsPaEntry.setPaDataType(PaDataType.ENC_TIMESTAMP);
        tsPaEntry.setPaDataValue(paDataValue.encode());

        return tsPaEntry;
    }

    public void setContext(KrbContext context) {
        this.context = context;
    }

    public void setHostAddresses(List<HostAddress> hostAddresses) {
        this.hostAddresses = hostAddresses;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    public boolean isPreauthRequired() {
        return preauthRequired;
    }

    public void setPreauthRequired(boolean preauthRequired) {
        this.preauthRequired = preauthRequired;
    }

    public List<EncryptionType> getEncryptionTypes() {
        if (encryptionTypes == null) {
            encryptionTypes = context.getConfig().getEncryptionTypes();
        }
        return encryptionTypes;
    }

    public void setEncryptionTypes(List<EncryptionType> encryptionTypes) {
        this.encryptionTypes = encryptionTypes;
    }

    public EncryptionType getChosenEncryptionType() {
        return chosenEncryptionType;
    }

    public void setChosenEncryptionType(EncryptionType chosenEncryptionType) {
        this.chosenEncryptionType = chosenEncryptionType;
    }

    public int generateNonce() {
        return context.generateNonce();
    }

    public int getChosenNonce() {
        return chosenNonce;
    }

    public void setChosenNonce(int nonce) {
        this.chosenNonce = nonce;
    }

    public EncryptionKey getClientKey() throws KrbException {
        if (clientKey == null) {
            clientKey = EncryptionHandler.string2Key(getClientPrincipal().getName(),
                context.getPassword(), getChosenEncryptionType());
        }
        return clientKey;
    }

    public long getTicketValidTime() {
        return context.getTicketValidTime();
    }

    public KerberosTime getTicketTillTime() {
        long now = System.currentTimeMillis();
        return new KerberosTime(now + KerberosTime.MINUTE * 60 * 1000);
    }

    public PrincipalName getClientPrincipal() {
        return context.getClientPrincipal();
    }

    public PrincipalName getServerPrincipal() {
        return context.getServerPrincipal();
    }

    public void addHost(String hostNameOrIpAddress) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(hostNameOrIpAddress);
        hostAddresses.add(new HostAddress(address));
    }
}
