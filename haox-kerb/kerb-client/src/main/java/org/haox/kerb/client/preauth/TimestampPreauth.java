package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.TimestampPreauthBase;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

import java.util.Collections;
import java.util.List;

public class TimestampPreauth extends TimestampPreauthBase implements KrbPreauth {

    private KrbContext context;

    public void init(KrbContext context) {
        this.context = context;
    }

    @Override
    public PreauthRequestContext initRequestContext(PreauthCallback preauthCallback) {
        return null;
    }

    @Override
    public void prepareQuestions(PreauthCallback preauthCallback,
                                 PreauthRequestContext requestContext, KrbOptions preauthOptions) {

    }

    @Override
    public List<EncryptionType> getEncTypes(PreauthCallback preauthCallback,
                                            PreauthRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(PreauthCallback preauthCallback,
                                  PreauthRequestContext requestContext, KrbOptions options) {
        
    }

    @Override
    public void process(PreauthCallback preauthCallback,
                        PreauthRequestContext requestContext,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        outPadata.addElement(makeEntry(preauthCallback));
    }

    @Override
    public void tryAgain(PreauthCallback preauthCallback, PreauthRequestContext requestContext,
                         PaDataType preauthType, PaData errPadata, PaData outPadata) {

    }

    @Override
    public PaFlags getFlags(PreauthCallback preauthCallback,
                            PreauthRequestContext requestContext, PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    @Override
    public void destroy() {

    }

    private PaDataEntry makeEntry(PreauthCallback preauthCallback) throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        paTs.setPaTimestamp(preauthCallback.getPreauthTime());

        EncryptedData paDataValue = EncryptionUtil.seal(paTs,
                preauthCallback.getAsKey(), KeyUsage.AS_REQ_PA_ENC_TS);
        PaDataEntry tsPaEntry = new PaDataEntry();
        tsPaEntry.setPaDataType(PaDataType.ENC_TIMESTAMP);
        tsPaEntry.setPaDataValue(paDataValue.encode());

        return tsPaEntry;
    }
}
