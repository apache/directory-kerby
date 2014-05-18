package org.haox.kerb.common.transport.accept;

import org.haox.kerb.common.dispatch.KrbDispatcher;
import org.haox.kerb.common.KrbRunnable;
import org.haox.kerb.common.event.TransportEvent;
import org.haox.kerb.common.transport.KrbTransport;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class KrbAcceptor extends KrbRunnable {
    protected String address;
    protected short listenPort;
    protected Selector selector = null;

    private KrbDispatcher dispatcher;

    public KrbAcceptor(String address, short listenPort) {
        this.address = address;
        this.listenPort = listenPort;
    }

    public void start() {
        try {
            doStart();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected void doStart() throws IOException {
        selector = Selector.open();
    }

    @Override
    protected boolean loopOnce() throws Exception {
        selector.select();
        Set<SelectionKey> selectionKeys = selector.selectedKeys();
        Iterator<SelectionKey> iterator = selectionKeys.iterator();
        while (iterator.hasNext()) {
            SelectionKey selectionKey = iterator.next();
            iterator.remove();
            dealKey(selectionKey);
        }
        return false;
    }

    protected abstract void dealKey(SelectionKey selectionKey) throws IOException;

    protected void onNewTransport(KrbTransport transport) {
        dispatcher.dispatch(new TransportEvent(transport));
    }
}
