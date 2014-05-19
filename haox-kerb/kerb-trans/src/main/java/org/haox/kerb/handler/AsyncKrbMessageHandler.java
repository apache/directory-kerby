package org.haox.kerb.handler;

import org.haox.kerb.Actor;
import org.haox.kerb.event.KrbMessageEvent;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.transport.Transport;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public abstract class AsyncKrbMessageHandler extends Actor implements KrbMessageHandler {

    private final BlockingQueue<KrbMessageEvent> eventQueue;

    public AsyncKrbMessageHandler() {
        super();
        this.eventQueue = new LinkedBlockingQueue<KrbMessageEvent>();
    }

    @Override
    public void handleMessage(KrbMessageEvent event) {
        eventQueue.add(event);
    }

    protected void process(KrbMessageEvent event) {
        KrbMessage message = event.getMessage();
        Transport transport = event.getTransport();

        KrbHandleContext hctx = new KrbHandleContext(transport);
        handleMessage(hctx, message);
    }

    protected abstract void handleMessage(KrbHandleContext hctx, KrbMessage message);

    @Override
    protected boolean loopOnce() {
        KrbMessageEvent event;
        try {
            event = eventQueue.take();
        } catch(InterruptedException ie) {
            if (!isStopped()) {
                //LOG.warn("AsyncDispatcher thread interrupted", ie);
            }
            return true;
        }
        if (event != null) {
            process(event);
        }

        return false;
    }
}

