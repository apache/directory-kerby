package org.haox.kerb.dispatch;

import org.haox.kerb.event.Event;
import org.haox.kerb.handler.Handler;

public interface Dispatcher {

    public void dispatch(Event event);

    public void register(Handler handler);

}
