package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.Preauth;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.List;

public interface KrbPreauth extends Preauth {

    public String getName();

    /**
     * Initializing preauth plugin context
     */
    public void init(KrbContext context);

    /**
     * Initializing request context
     */
    public PreauthRequestContext initRequestContext(PreauthCallback preauthCallback);

    /**
     * Prepare questions to prompt to you asking for credential
     */
    public void prepareQuestions(PreauthCallback preauthCallback,
                                  PreauthRequestContext requestContext, KrbOptions preauthOptions);

    /**
     * Get supported encryption types
     */
    public List<EncryptionType> getEncTypes(PreauthCallback preauthCallback,
                                            PreauthRequestContext requestContext);

    /**
     * Set krb options passed from user
     */
    public void setPreauthOptions(PreauthCallback preauthCallback,
                                  PreauthRequestContext requestContext, KrbOptions preauthOptions);

    /**
     * Process server returned paData and return back any result paData
     */
    public void process(PreauthCallback preauthCallback,
                        PreauthRequestContext requestContext,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException;

    /**
     * When another request to server in the 4 pass, any paData to provide?
     */
    public void tryAgain(PreauthCallback preauthCallback, PreauthRequestContext requestContext,
                         PaDataType preauthType, PaData errPadata, PaData outPadata);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(PreauthCallback preauthCallback,
                            PreauthRequestContext requestContext, PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy();

}
