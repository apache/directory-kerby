package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.Preauth;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;


public interface KdcPreauth extends Preauth {

    public String getName();

    public void init(KdcContext context);

    /**
     * Optional: provide pa_data to send to the client as part of the "you need to
     * use preauthentication" error.
     */
    public void provideEData(PreauthContext preauthContext) throws KrbException;

    /**
     * Optional: verify preauthentication data sent by the client, setting the
     * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
     * field as appropriate.
     */
    public void verify(PreauthContext preauthContext, PaDataEntry paData) throws KrbException;

    /**
     * Optional: generate preauthentication response data to send to the client as
     * part of the AS-REP.
     */
    public void providePaData(PreauthContext preauthContext, PaData paData);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy();

}
