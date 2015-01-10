package org.apache.kerberos.kerb.client.preauth;

import org.apache.kerberos.kerb.client.KrbContext;
import org.apache.kerberos.kerb.client.KrbOptions;
import org.apache.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerberos.kerb.preauth.PaFlag;
import org.apache.kerberos.kerb.preauth.PaFlags;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

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
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        return null;
    }

    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) throws KrbException {

        kdcRequest.needAsKey();
    }

    @Override
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext, KrbOptions options) {

    }

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext, PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        return false;
    }

    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                            PluginRequestContext requestContext, PaDataType preauthType,
                            PaData errPadata, PaData outPadata) {
        return false;
    }

    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    @Override
    public void destroy() {

    }

}
