package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.common.preauth.PaFlag;
import org.haox.kerb.common.preauth.PaFlags;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataType;

public abstract class AbstractPreauth implements Preauth {

    private KrbContext context;

    public void init(KrbContext context) {
        this.context = context;
    }

    @Override
    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException {

    }

    @Override
    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {

    }

    @Override
    public void tryAgain(PreauthContext preauthContext, PaData paData) {

    }

    @Override
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    protected KrbContext getContext() {
        return context;
    }

    @Override
    public void destroy(KrbContext context) {

    }
}
