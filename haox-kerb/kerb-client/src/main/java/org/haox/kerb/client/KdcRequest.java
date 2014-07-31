package org.haox.kerb.client;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.common.KerberosKeyFactory;
import org.haox.kerb.crypto2.EncryptionHandler;
import org.haox.kerb.crypto2.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public abstract class KdcRequest {
    private KrbContext context;

    private List<HostAddress> hostAddresses = new ArrayList<HostAddress>();
    private KdcOptions kdcOptions = new KdcOptions();
    private boolean preAuthEnabled = false;
    private List<EncryptionType> etypes;
    private EncryptionType chosenEtype;
    private EncryptionKey clientKey;
    private int chosenNonce;

    public KdcRequest(KrbContext context) {
        this.context = context;
    }

    public abstract KdcReq makeKdcRequest() throws KrbException;

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

    protected byte[] decryptWithClientKey(EncryptedData data, KeyUsage usage) throws KrbException {
        return EncryptionHandler.decrypt(data, getClientKey(), usage);
    }

    protected PaDataEntry makeTimeStampPaDataEntry() throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        long paTimestamp = System.currentTimeMillis();
        paTs.setPaTimestamp(new KerberosTime(paTimestamp));

        EncryptedData paDataValue = encodingAndEncryptWithClientKey(paTs, KeyUsage.AS_REQ_PA_ENC_TIMESTAMP_WITH_CKEY);
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

    public boolean isPreAuthEnabled() {
        return preAuthEnabled;
    }

    public void setPreAuthEnabled(boolean preAuthEnabled) {
        this.preAuthEnabled = preAuthEnabled;
    }

    public List<EncryptionType> getEtypes() {
        if (etypes == null) {
            etypes = context.getDefaultEtypes();
        }
        return etypes;
    }

    public void setEtypes(List<EncryptionType> etypes) {
        this.etypes = etypes;
    }

    public EncryptionType getChosenEtype() {
        return chosenEtype;
    }

    public void setChosenEtype(EncryptionType chosenEtype) {
        this.chosenEtype = chosenEtype;
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
            clientKey = KerberosKeyFactory.string2Key(getClientPrincipal(),
                context.getPassword(), getChosenEtype());
        }
        return clientKey;
    }

    public long getTicketValidTime() {
        return context.getTicketValidTime();
    }

    public long getTicketTillTime() {
        return KerberosTime.MINUTE * 60;
    }

    public String getClientPrincipal() {
        return context.getClientPrincipal();
    }

    public String getRealm() {
        return context.getRealm();
    }

    public String getServerPrincipal() {
        return context.getServerPrincipal();
    }

    public void addHost(String hostNameOrIpAddress) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(hostNameOrIpAddress);
        hostAddresses.add(new HostAddress(address));
    }
}
