package org.haox.kerb.server.replay;

import java.util.HashSet;
import java.util.Set;

public class SimpleCacheService implements CacheService {
    private Set<RequestRecord> requests;

    public SimpleCacheService() {
        requests = new HashSet<RequestRecord>();
    }

    @Override
    public boolean checkAndCache(RequestRecord request) {
        if (requests.contains(request)) {
            return true;
        } else {
            requests.add(request);
        }
        return false;
    }

    @Override
    public void clear() {
        requests.clear();
    }
}
