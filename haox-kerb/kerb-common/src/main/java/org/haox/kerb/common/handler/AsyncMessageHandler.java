package org.haox.kerb.common.handler;

import org.haox.kerb.common.KrbRunnable;
import org.haox.kerb.common.event.KrbEvent;
import org.haox.kerb.common.event.MessageEvent;
import org.haox.kerb.common.transport.KrbTransport;
import org.haox.kerb.spec.type.common.KrbMessage;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public abstract class AsyncMessageHandler extends KrbRunnable implements MessageHandler {

    private final BlockingQueue<MessageEvent> eventQueue;

    public AsyncMessageHandler() {
        super();
        this.eventQueue = new LinkedBlockingQueue<MessageEvent>();
    }


    @Override
    public void handleMessage(MessageEvent event) {
        eventQueue.add(event);
    }

    @Override
    public void handle(KrbEvent event) {
        if (! (event instanceof MessageEvent)) {
            throw new RuntimeException("Message dispatcher met non-message event");
        }

        handleMessage((MessageEvent) event);
    }

    protected void process(MessageEvent event) {
        KrbMessage message = event.getMessage();
        KrbTransport transport = event.getTransport();

        HandleContext hctx = new HandleContext(transport);
        handleMessage(hctx, message);
    }

    protected abstract void handleMessage(HandleContext hctx, KrbMessage message);

    @Override
    protected boolean loopOnce() {
        MessageEvent event;
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

