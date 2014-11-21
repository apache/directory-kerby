package org.haox.kerb.client.preauth.token;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.KrbPreauth;
import org.haox.kerb.client.preauth.PreauthCallback;
import org.haox.kerb.client.preauth.PreauthRequestContext;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.token.TokenPreauthBase;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.token.KerbToken;

import java.util.Collections;
import java.util.List;

public class TokenPreauth extends TokenPreauthBase implements KrbPreauth {

    private KrbContext context;
    private TokenContext tokenContext;

    public void init(KrbContext context) {
        this.context = context;
        this.tokenContext = new TokenContext();
    }

    @Override
    public PreauthRequestContext initRequestContext(PreauthCallback preauthCallback) {
        TokenRequestContext reqCtx = new TokenRequestContext();

        return reqCtx;
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

        tokenContext.usingIdToken = options.getBooleanOption(KrbOption.TOKEN_USING_IDTOKEN);
        if (tokenContext.usingIdToken) {
            if (options.contains(KrbOption.TOKEN_USER_ID_TOKEN)) {
                tokenContext.token =
                        (KerbToken) options.getOptionValue(KrbOption.TOKEN_USER_ID_TOKEN);
            }
        } else {
            if (options.contains(KrbOption.TOKEN_USER_AC_TOKEN)) {
                tokenContext.token =
                        (KerbToken) options.getOptionValue(KrbOption.TOKEN_USER_AC_TOKEN);
            }
        }

    }

    @Override
    public void process(PreauthCallback preauthCallback,
                        PreauthRequestContext requestContext,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {

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

}
