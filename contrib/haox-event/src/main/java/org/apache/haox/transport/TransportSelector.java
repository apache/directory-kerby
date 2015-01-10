package org.apache.haox.transport;

import org.apache.haox.event.Dispatcher;
import org.apache.haox.event.LongRunningEventHandler;
import org.apache.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;

public abstract class TransportSelector extends LongRunningEventHandler {

    protected Selector selector;
    protected TransportHandler transportHandler;

    public TransportSelector(TransportHandler transportHandler) {
        super();
        this.transportHandler = transportHandler;
    }

    @Override
    public void setDispatcher(Dispatcher dispatcher) {
        super.setDispatcher(dispatcher);
        dispatcher.register(transportHandler);
    }

    @Override
    public void init() {
        super.init();

        try {
            selector = Selector.open();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void loopOnce() {
        try {
            selectOnce();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    protected void selectOnce() throws IOException {
        if (selector.isOpen() && selector.select(10) > 0 && selector.isOpen()) {
            Set<SelectionKey> selectionKeys = selector.selectedKeys();
            Iterator<SelectionKey> iterator = selectionKeys.iterator();
            while (iterator.hasNext()) {
                SelectionKey selectionKey = iterator.next();
                dealKey(selectionKey);
                iterator.remove();
            }
            selectionKeys.clear();
        }
    }

    protected void dealKey(SelectionKey selectionKey) throws IOException {
        transportHandler.helpHandleSelectionKey(selectionKey);
    }

    protected void onNewTransport(Transport transport) {
        transport.setDispatcher(getDispatcher());
        dispatch(TransportEvent.createNewTransportEvent(transport));
    }

    @Override
    public void stop() {
        super.stop();

        try {
            selector.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
