package org.haox.kerb.server.preauth;

import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

public class TimestampPreauth extends AbstractPreauth {

    @Override
    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException {
        paData.addElement(makeEntry(preauthContext));
    }

    @Override
    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {
        paData.addElement(makeEntry(preauthContext));
    }

    private PaDataEntry makeEntry(PreauthContext preauthContext) throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        paTs.setPaTimestamp(preauthContext.getPreauthTime());

        EncryptedData paDataValue = EncryptionUtil.seal(paTs,
                preauthContext.getAsKey(), KeyUsage.AS_REQ_PA_ENC_TS);
        PaDataEntry tsPaEntry = new PaDataEntry();
        tsPaEntry.setPaDataType(PaDataType.ENC_TIMESTAMP);
        tsPaEntry.setPaDataValue(paDataValue.encode());

        return tsPaEntry;
    }
}
