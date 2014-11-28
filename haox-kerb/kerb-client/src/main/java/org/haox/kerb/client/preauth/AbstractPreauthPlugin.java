package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.Collections;
import java.util.List;

public class AbstractPreauthPlugin implements KrbPreauth {

    private PreauthPluginMeta pluginMeta;
    protected KrbContext context;

    public AbstractPreauthPlugin(PreauthPluginMeta meta) {
        this.pluginMeta = meta;
    }

    @Override
    public String getName() {
        return pluginMeta.getName();
    }

    public int getVersion() {
        return pluginMeta.getVersion();
    }

    public PaDataType[] getPaTypes() {
        return pluginMeta.getPaTypes();
    }

    public void init(KrbContext context) {
        this.context = context;
    }

    @Override
    public PluginRequestContext initRequestContext(KrbContext krbContext,
                                                   KdcRequest kdcRequest,
                                                   PreauthCallback preauthCallback) {
        return null;
    }

    @Override
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PreauthCallback preauthCallback,
                                 PluginRequestContext requestContext) throws KrbException {

        preauthCallback.needAsKey(krbContext, kdcRequest);
    }

    @Override
    public List<EncryptionType> getEncTypes(KrbContext krbContext,
                                            KdcRequest kdcRequest,
                                            PreauthCallback preauthCallback,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KrbContext krbContext,
                                  KdcRequest kdcRequest,
                                  PreauthCallback preauthCallback,
                                  PluginRequestContext requestContext,
                                  KrbOptions options) {

    }

    public void tryFirst(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KrbContext krbContext,
                           KdcRequest kdcRequest,
                           PreauthCallback preauthCallback,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        return false;
    }

    @Override
    public boolean tryAgain(KrbContext krbContext,
                            KdcRequest kdcRequest,
                            PreauthCallback preauthCallback,
                            PluginRequestContext requestContext,
                            PaDataType preauthType,
                            PaData errPadata,
                            PaData outPadata) {
        return false;
    }

    @Override
    public PaFlags getFlags(KrbContext krbContext,
                            PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    @Override
    public void destroy(KrbContext krbContext) {

    }

}
