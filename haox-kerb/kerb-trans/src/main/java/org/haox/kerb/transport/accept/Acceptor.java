package org.haox.kerb.transport.accept;

import org.haox.kerb.Actor;
import org.haox.kerb.dispatch.Dispatcher;
import org.haox.kerb.event.NewTransportEvent;
import org.haox.kerb.transport.Transport;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class Acceptor extends Actor {
    protected String address;
    protected short listenPort;
    protected Selector selector = null;

    private Dispatcher dispatcher;

    public Acceptor(String address, short listenPort) {
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

    protected void onNewTransport(Transport transport) {
        dispatcher.dispatch(new NewTransportEvent(transport));
    }
}
