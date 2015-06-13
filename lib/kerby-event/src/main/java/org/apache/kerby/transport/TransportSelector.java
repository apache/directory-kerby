/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.transport;

import org.apache.kerby.event.Dispatcher;
import org.apache.kerby.event.LongRunningEventHandler;
import org.apache.kerby.transport.event.TransportEvent;

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
