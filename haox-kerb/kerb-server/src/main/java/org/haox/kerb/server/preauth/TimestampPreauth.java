package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.TimestampPreauthBase;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

public class TimestampPreauth extends TimestampPreauthBase implements KdcPreauth {

    private KdcContext context;

    public void init(KdcContext context) {
        this.context = context;
    }

    @Override
    public void provideEData(PreauthContext preauthContext) throws KrbException {

    }

    @Override
    public void verify(PreauthContext preauthContext, PaData paData) throws KrbException {

    }

    @Override
    public void providePaData(PreauthContext preauthContext, PaData paData) {

    }

    @Override
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType) {
        return null;
    }

    @Override
    public void destroy() {

    }

    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {
        paData.addElement(makeEntry(preauthContext));
    }

    private PaDataEntry makeEntry(PreauthContext preauthContext) throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        //paTs.setPaTimestamp(preauthContext.getPreauthTime());

        EncryptedData paDataValue = null;//EncryptionUtil.seal(paTs,
                //preauthContext.getAsKey(), KeyUsage.AS_REQ_PA_ENC_TS);
        PaDataEntry tsPaEntry = new PaDataEntry();
        tsPaEntry.setPaDataType(PaDataType.ENC_TIMESTAMP);
        tsPaEntry.setPaDataValue(paDataValue.encode());

        return tsPaEntry;
    }
}
