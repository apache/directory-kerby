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

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A combined and mixed network server handling UDP and TCP.
 */
public class NettyKdcNetwork {
    private KdcContext kdcContext;
    private InetSocketAddress tcpAddress;
    private InetSocketAddress udpAddress;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private EventLoopGroup group;
    private DefaultEventExecutorGroup executorGroup;
    private static final Logger LOG = LoggerFactory.getLogger(NettyKdcNetwork.class);

    public void init(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
        // Configure the server.
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        executorGroup = new DefaultEventExecutorGroup(10); //TODO: to configure.
    }

    public void listen(InetSocketAddress tcpAddress,
                       InetSocketAddress udpAddress) throws IOException {
        this.tcpAddress = tcpAddress;
        this.udpAddress = udpAddress;
    }

    public void start() {
        try {
            doStart();
        } catch (Exception e) {
            LOG.error("Error occurred while starting the netty kdc network.");
        }
    }

    private void doStart() throws Exception {
        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 100)
                .handler(new LoggingHandler(LogLevel.INFO))
                .childHandler(createChannelInitializer());

        // Start the server.
        b.bind(tcpAddress.getPort());
        if (udpAddress != null) {
            startUDPServer();
        }
    }

    private void startUDPServer() {
        this.group = new NioEventLoopGroup();
        Bootstrap b = new Bootstrap();
        b.group(group).channel(NioDatagramChannel.class)
                .option(ChannelOption.SO_BROADCAST, true)
                .handler((ChannelHandler) new NettyKdcUdpServerHandler(kdcContext));
        b.bind(udpAddress.getPort());
    }

    static class KrbMessageDecoder extends LengthFieldBasedFrameDecoder {
        KrbMessageDecoder() {
            super(1 * 1024 * 1024, 0, 4, 0, 4, true);
        }
    }

    private ChannelInitializer<SocketChannel> createChannelInitializer() {
        return new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) throws Exception {
                ChannelPipeline p = ch.pipeline();
                p.addLast(new KrbMessageDecoder());
                p.addLast(executorGroup,
                        "KDC_HANDLER",
                        new NettyKdcHandler(kdcContext));
            }
        };
    }

    public synchronized void stop() {
        // Shut down all event loops to terminate all threads.
        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
        if (udpAddress != null) {
            group.shutdownGracefully();
        }

        try {
            bossGroup.terminationFuture().sync();
            workerGroup.terminationFuture().sync();
            if (udpAddress != null) {
                group.terminationFuture().sync();
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
