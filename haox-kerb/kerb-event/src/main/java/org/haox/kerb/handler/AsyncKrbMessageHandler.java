package org.haox.kerb.handler;

import org.haox.kerb.event.Event;
import org.haox.kerb.event.EventType;
import org.haox.kerb.event.KrbMessageEvent;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

public abstract class AsyncKrbMessageHandler extends AsyncEventHandler {

    public AsyncKrbMessageHandler() {
        super();
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                EventType.NEW_INBOUND_KRBMESSAGE,
                EventType.NEW_OUTBOUND_KRBMESSAGE
        };
    }

    @Override
    public void process(Event event) {
        KrbMessageEvent ke = (KrbMessageEvent) event;
        KrbMessage message = ke.getMessage();
        Transport transport = ke.getTransport();

        KrbHandleContext hctx = new KrbHandleContext(transport);
        process(hctx, message);
    }

    protected abstract void process(KrbHandleContext hctx, KrbMessage message);

}

