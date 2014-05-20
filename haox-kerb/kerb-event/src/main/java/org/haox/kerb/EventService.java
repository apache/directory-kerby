package org.haox.kerb;

import org.haox.kerb.dispatch.AsyncDispatcher;
import org.haox.kerb.dispatch.Dispatcher;

public class EventService {

    private static Dispatcher instance = null;

    public static Dispatcher getInstance() {
        if (instance == null) {
            instance = new AsyncDispatcher();
        }
        return instance;
    }

}
