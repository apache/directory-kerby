package org.apache.kerberos.kerb.client.preauth.builtin;

import org.apache.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerberos.kerb.preauth.PaFlag;
import org.apache.kerberos.kerb.preauth.PaFlags;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.builtin.EncTsPreauthMeta;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerberos.kerb.spec.common.KeyUsage;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerberos.kerb.spec.pa.PaEncTsEnc;

public class EncTsPreauth extends AbstractPreauthPlugin {

    public EncTsPreauth() {
        super(new EncTsPreauthMeta());
    }

    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) throws KrbException {

        kdcRequest.needAsKey();
    }

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(kdcRequest));
    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(kdcRequest));

        return true;
    }

    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    private PaDataEntry makeEntry(KdcRequest kdcRequest) throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        paTs.setPaTimestamp(kdcRequest.getPreauthTime());

        EncryptedData paDataValue = EncryptionUtil.seal(paTs,
                kdcRequest.getAsKey(), KeyUsage.AS_REQ_PA_ENC_TS);
        PaDataEntry tsPaEntry = new PaDataEntry();
        tsPaEntry.setPaDataType(PaDataType.ENC_TIMESTAMP);
        tsPaEntry.setPaDataValue(paDataValue.encode());

        return tsPaEntry;
    }
}
