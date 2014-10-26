package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.common.preauth.PaFlags;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataType;

public interface Preauth {

    public void init(KrbContext context);

    /**
     * When first request to server, any paData to provide?
     */
    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException;

    /**
     * Process server returned paData and return back any result paData
     */
    public void process(PreauthContext preauthContext, PaData paData) throws KrbException;

    /**
     * When another request to server in the 4 pass, any paData to provide?
     */
    public void tryAgain(PreauthContext preauthContext, PaData paData);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy(KrbContext context);

}
