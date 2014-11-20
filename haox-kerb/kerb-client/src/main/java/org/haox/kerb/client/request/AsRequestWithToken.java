package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.token.KerbToken;

public class AsRequestWithToken extends AsRequest {

    public AsRequestWithToken(KrbContext context) {
        super(context);
    }

    @Override
    public void process() throws KrbException {
        throw new RuntimeException("To be implemented");
    }

    @Override
    protected KrbOptions getPreauthOptions() {
        KrbOptions results = new KrbOptions();

        KrbOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.TOKEN_USING_IDTOKEN));
        results.add(krbOptions.getOption(KrbOption.TOKEN_USER_ID_TOKEN));
        results.add(krbOptions.getOption(KrbOption.TOKEN_USER_AC_TOKEN));

        return results;
    }
}
