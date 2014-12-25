package org.haox.kerb.client.preauth.builtin;

import org.haox.kerb.client.preauth.AbstractPreauthPlugin;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.builtin.EncTsPreauthMeta;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.EncryptedData;
import org.haox.kerb.spec.common.KeyUsage;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataEntry;
import org.haox.kerb.spec.pa.PaDataType;
import org.haox.kerb.spec.pa.PaEncTsEnc;

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
