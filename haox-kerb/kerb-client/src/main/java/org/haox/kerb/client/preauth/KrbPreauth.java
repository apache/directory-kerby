package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.List;

/**
 * Client side preauth plugin module
 */
public interface KrbPreauth extends PreauthPluginMeta {

    /**
     * Initializing preauth plugin context
     */
    public void init(KrbContext krbContext);

    /**
     * Initializing request context
     */
    public PluginRequestContext initRequestContext(KrbContext krbContext,
                                                    KdcRequest kdcRequest,
                                                    PreauthCallback preauthCallback);

    /**
     * Prepare questions to prompt to you asking for credential
     */
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PreauthCallback preauthCallback,
                                 PluginRequestContext requestContext) throws KrbException;

    /**
     * Get supported encryption types
     */
    public List<EncryptionType> getEncTypes(KrbContext krbContext,
                                            KdcRequest kdcRequest,
                                            PreauthCallback preauthCallback,
                                            PluginRequestContext requestContext);

    /**
     * Set krb options passed from user
     */
    public void setPreauthOptions(KrbContext krbContext,
                                  KdcRequest kdcRequest,
                                  PreauthCallback preauthCallback,
                                  PluginRequestContext requestContext,
                                  KrbOptions preauthOptions);

    /**
     * Attempt to try any initial padata derived from user options
     */
    public void tryFirst(KrbContext krbContext,
                        KdcRequest kdcRequest,
                        PreauthCallback preauthCallback,
                        PluginRequestContext requestContext,
                        PaData outPadata) throws KrbException;

    /**
     * Process server returned paData and return back any result paData
     * Return true indicating padata is added
     */
    public boolean process(KrbContext krbContext,
                        KdcRequest kdcRequest,
                        PreauthCallback preauthCallback,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException;

    /**
     * When another request to server in the 4 pass, any paData to provide?
     * Return true indicating padata is added
     */
    public boolean tryAgain(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PluginRequestContext requestContext,
                         PaDataType preauthType,
                         PaData errPadata,
                         PaData outPadata);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(KrbContext krbContext,
                            PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy(KrbContext krbContext);

}
