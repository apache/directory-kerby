package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataEntry;
import org.haox.kerb.spec.pa.PaDataType;

public class AbstractPreauthPlugin implements KdcPreauth {

    private PreauthPluginMeta pluginMeta;

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

    @Override
    public void initWith(KdcContext kdcContext) {

    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        return null;
    }

    @Override
    public void provideEdata(KdcRequest kdcRequest, PluginRequestContext requestContext,
            PaData outPaData) throws KrbException {

    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {
        return false;
    }

    @Override
    public void providePaData(KdcRequest kdcRequest, PluginRequestContext requestContext,
                              PaData paData) {

    }

    @Override
    public PaFlags getFlags(KdcRequest kdcRequest, PluginRequestContext requestContext,
                            PaDataType paType) {
        return null;
    }

    @Override
    public void destroy() {

    }
}
