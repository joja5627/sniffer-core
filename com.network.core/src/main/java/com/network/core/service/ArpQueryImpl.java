package com.network.core.service;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Created by ddubson on 3/5/17.
 */
public class ArpQueryImpl implements ArpQuery {
    private static final String COUNT_KEY
            = ArpQueryImpl.class.getName() + ".count";
    private static final int COUNT
            = Integer.getInteger(COUNT_KEY, 1);

    private static final String READ_TIMEOUT_KEY
            = ArpQueryImpl.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT
            = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY
            = ArpQueryImpl.class.getName() + ".snaplen";
    private static final int SNAPLEN
            = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private MacAddress resolvedMacAddress;

    private MacAddress resolveSrcMacAddr(PcapNetworkInterface sNif) {
        return MacAddress.getByName(sNif.getLinkLayerAddresses().get(0).toString());
    }

    @Override
    public MacAddress arp(String nif, String srcIpAddr, String dstIpAddress) {
        PcapHandle recvHandle = null, sendHandle = null;

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            PcapNetworkInterface sNif = Pcaps.getDevByName(nif);
            recvHandle
                    = sNif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            sendHandle
                    = sNif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            recvHandle.setFilter(
                    "arp and src host " + dstIpAddress
                            + " and dst host " + srcIpAddr
                            + " and ether dst " + Pcaps.toBpfString(resolveSrcMacAddr(sNif)),
                    BpfProgram.BpfCompileMode.OPTIMIZE
            );

            PacketListener listener
                    = packet -> {
                if (packet.contains(ArpPacket.class)) {
                    ArpPacket arp = packet.get(ArpPacket.class);
                    if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                        resolvedMacAddress = arp.getHeader().getSrcHardwareAddr();
                    }
                }
//                System.out.println(packet);
            };

            Task t = new Task(recvHandle, listener);
            pool.execute(t);

            ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
            try {
                arpBuilder
                        .hardwareType(ArpHardwareType.ETHERNET)
                        .protocolType(EtherType.IPV4)
                        .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                        .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                        .operation(ArpOperation.REQUEST)
                        .srcHardwareAddr(resolveSrcMacAddr(sNif))
                        .srcProtocolAddr(InetAddress.getByName(srcIpAddr))
                        .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                        .dstProtocolAddr(InetAddress.getByName(dstIpAddress));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e);
            }

            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .srcAddr(resolveSrcMacAddr(sNif))
                    .type(EtherType.ARP)
                    .payloadBuilder(arpBuilder)
                    .paddingAtBuild(true);

            for (int i = 0; i < COUNT; i++) {
                Packet p = etherBuilder.build();
//                System.out.println(p);
                sendHandle.sendPacket(p);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            System.out.println("native ex: " + e.getMessage());
        } finally {
            if (recvHandle != null && recvHandle.isOpen()) {
                recvHandle.close();
            }
            if (sendHandle != null && sendHandle.isOpen()) {
                sendHandle.close();
            }
            if (pool != null && !pool.isShutdown()) {
                pool.shutdown();
            }

            System.out.println(dstIpAddress + " was resolved to " + resolvedMacAddress);
        }

        return resolvedMacAddress;
    }

    private static class Task implements Runnable {

        private PcapHandle handle;
        private PacketListener listener;

        public Task(PcapHandle handle, PacketListener listener) {
            this.handle = handle;
            this.listener = listener;
        }

        @Override
        public void run() {
            try {
                handle.loop(COUNT, listener);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                e.printStackTrace();
            }
        }

    }
}
