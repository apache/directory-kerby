package org.haox.kerb.spec.type;

import org.haox.kerb.spec.*;

public class KrbFactory {
    private static KrbFactory instance = new KrbFactory();

    public static void register(KrbFactory factory) {
        instance = factory;
    }

    public static KrbFactory get() {
        return instance;
    }

    public KrbType create(Class<? extends KrbType> type) throws KrbException {
        try {
            Class<? extends KrbType> classType = null;
            if (type.isInterface()) {
                classType = KrbTypes.getImpl(type);
            } else {
                classType = type;
            }
            return classType.newInstance();
        } catch (InstantiationException e) {
            KrbThrow.out(KrbTypeMessageCode.INVALID_KRB_TYPE);
        } catch (IllegalAccessException e) {
            KrbThrow.out(KrbTypeMessageCode.INVALID_KRB_TYPE);
        }

        return null;
    }
}
