package org.haox.kerb.spec;

import org.haox.kerb.spec.type.KrbType;

import java.util.HashMap;
import java.util.Map;

public class KrbTypes {
    private static Map<Class<? extends KrbType>, Class<? extends KrbType>> entries =
            new HashMap<Class<? extends KrbType>, Class<? extends KrbType>>();

    public static void implement(Class<? extends KrbType> inf, Class<? extends KrbType> impl) {
        entries.put(inf, impl);
    }

    public static Class<? extends KrbType> getImpl(Class<? extends KrbType> inf) throws KrbException {
        Class<? extends KrbType> impl = entries.get(inf);
        if (impl == null) {
            String fullName = inf.getCanonicalName();
            String simpleName = inf.getSimpleName();
            String fullClassName = fullName.replace(simpleName, "impl." + simpleName + "Impl");
            try {
                Class<?> aClass = inf.getClassLoader().loadClass(fullClassName);
                try {
                    impl = (Class<? extends KrbType>) aClass;
                    entries.put(inf, impl);
                } catch (ClassCastException e) {
                    KrbThrow.out(KrbTypeMessageCode.INVALID_KRB_IMPL, e);
                }
            } catch (ClassNotFoundException e) { }
        }
        if (impl == null) {
            KrbThrow.out(KrbTypeMessageCode.NO_IMPL_FOUND);
        }

        return impl;
    }

}
