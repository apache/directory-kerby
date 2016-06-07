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
package org.apache.kerby.kerberos.kdc.impl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class NettyKdcHandler extends ChannelInboundHandlerAdapter {
    private final KdcHandler myKdcHandler;
    private static final Logger LOG = LoggerFactory.getLogger(NettyKdcHandler.class);

    public NettyKdcHandler(KdcContext kdcContext) {
        this.myKdcHandler = new KdcHandler(kdcContext);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx,
                            Object msg) throws Exception {
        ByteBuf byteBuf = (ByteBuf) msg;
        byte[] msgBytes = new byte[byteBuf.readableBytes()];
        byteBuf.readBytes(msgBytes);
        ByteBuffer requestMessage = ByteBuffer.wrap(msgBytes);
        byteBuf.release();

        InetSocketAddress clientAddress =
                (InetSocketAddress) ctx.channel().remoteAddress();
        boolean isTcp = true; //TODO:
        try {
            ByteBuffer responseMessage = myKdcHandler.handleMessage(requestMessage,
                    isTcp, clientAddress.getAddress());
            ctx.writeAndFlush(Unpooled.wrappedBuffer(responseMessage));
        } catch (Exception e) {
            LOG.error("Error occurred while processing request:"
                    + e);
            e.printStackTrace();
        }
    }

    /**
     * Calls {@link ChannelHandlerContext#fireExceptionCaught(Throwable)} to
     * forward to the next {@link ChannelHandler} in the {@link ChannelPipeline}
     *
     * Sub-classes may override this method to change behavior.
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
            throws Exception {
        cause.printStackTrace();
        ctx.fireExceptionCaught(cause);
    }
}
