package org.haox.kerb.client.preauth.builtin;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.AbstractPreauthPlugin;
import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.builtin.EncTsPreauthMeta;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

public class EncTsPreauth extends AbstractPreauthPlugin {

    public EncTsPreauth() {
        super(new EncTsPreauthMeta());
    }

    @Override
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) throws KrbException {

        kdcRequest.needAsKey();
    }

    public void tryFirst(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(krbContext, kdcRequest));
    }

    @Override
    public boolean process(KrbContext krbContext,
                           KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(krbContext, kdcRequest));

        return true;
    }

    @Override
    public PaFlags getFlags(KrbContext krbContext,
                            PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    private PaDataEntry makeEntry(KrbContext krbContext,
                                  KdcRequest kdcRequest) throws KrbException {
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
