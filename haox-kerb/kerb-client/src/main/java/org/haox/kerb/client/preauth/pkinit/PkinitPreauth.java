package org.haox.kerb.client.preauth.pkinit;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.KrbPreauth;
import org.haox.kerb.client.preauth.PreauthCallback;
import org.haox.kerb.client.preauth.PreauthRequestContext;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.pkinit.PkinitPreauthBase;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.Collections;
import java.util.List;

public class PkinitPreauth extends PkinitPreauthBase implements KrbPreauth {

    private KrbContext context;
    private PkinitContext pkinitContext;

    public void init(KrbContext context) {
        this.context = context;
        this.pkinitContext = new PkinitContext();
    }

    @Override
    public PreauthRequestContext initRequestContext(PreauthCallback preauthCallback) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    @Override
    public List<EncryptionType> getEncTypes(PreauthCallback preauthCallback,
                                            PreauthRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(PreauthCallback preauthCallback,
                                  PreauthRequestContext requestContext, KrbOptions options) {
        if (options.contains(KrbOption.PKINIT_X509_IDENTITY)) {
            pkinitContext.identityOpts.identity =
                    options.getStringOption(KrbOption.PKINIT_X509_IDENTITY);
        }

        if (options.contains(KrbOption.PKINIT_X509_ANCHORS)) {
            pkinitContext.identityOpts.anchors.add(
                    options.getStringOption(KrbOption.PKINIT_X509_ANCHORS));
        }

        if (options.contains(KrbOption.PKINIT_USING_RSA)) {
            pkinitContext.pluginOpts.usingRsa =
                    options.getBooleanOption(KrbOption.PKINIT_USING_RSA);
        }

    }

    @Override
    public void tryFirst(PreauthCallback preauthCallback,
                         PreauthRequestContext requestContext, PaData paData) throws KrbException {

    }

    @Override
    public void process(PreauthCallback preauthCallback,
                        PreauthRequestContext requestContext, PaData paData) throws KrbException {

    }

    @Override
    public void tryAgain(PreauthCallback preauthCallback,
                         PreauthRequestContext requestContext, PaData paData) {

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

}
