package com.network.core.service;

import com.network.core.domain.NetworkMap;
import com.network.core.domain.PacketHeader;
import com.network.core.domain.PacketType;
import org.pcap4j.core.*;
import org.pcap4j.packet.TcpPacket;

public class NetworkDiscoveryService {
    private static final int LIST_ITEM_MAX = 1000;
    private Capture capture;
    private NetworkMap networkMap;
    private NetworkDevice localhost, gateway;
    private boolean isCapturing, isGatewayDetected, isPingReceived;
    private static final String PING_DST = "8.8.8.8";
    private static final int COUNT = -1;
    private static final int READ_TIME_OUT = 10; // [ms]
    private static final int SNAP_LENGTH = 65536; // [bytes]
    private int refreshCount = 0;
    private PcapHandle pcapHandle;
    String gatewayAddress;
    PcapNetworkInterface networkIface;


    public void runDiscovery() throws PcapNativeException {
//        isCapturing = true;
//        isGatewayDetected = false;
//        isPingReceived = false;
//
//
//
//        sendArp(networkIface, gatewayAddress);
    }
    private void startPacketListener() throws PcapNativeException {

        PacketListener listener = packet -> {
            if(packet instanceof TcpPacket){
//                System.out.
//                TcpPacket tcpPacket = new (TcpPacket) packet.get;
//                System.out.println(tcpPacket.getHeader().toString());
//                System.out.println(tcpPacket.getPayload().toString());
            }


            if (packet == null || packet.getPayload() == null) {
                return;
            }
            PacketHeader header = new PacketHeader(packet, localhost);

            switch (header.getProtocol()) {
                case ARP:
                    if (!isGatewayDetected) {
                        try {
                            receivedArpReply(gatewayAddress, header, networkIface);
                            System.out.println(packet.getHeader().toString());
                        } catch (PcapNativeException e) {
                            e.printStackTrace();
                        }
                    }
                    break;
                case ICMPv6:
                    try {
                            receivedPingReply(header, networkIface);
                        System.out.println(packet.getHeader().toString());
                        } catch (PcapNativeException e) {
                            e.printStackTrace();
                        }

                case ICMPv4:
                    try {

                        receivedPingReply(header, networkIface);
                        System.out.println(packet.getHeader().toString());
                    } catch (PcapNativeException e) {
                        e.printStackTrace();
                    }
                default:
                    System.out.println(packet.getHeader().toString());
                    System.out.println(packet.getRawData().toString());

            }

//            guiControllable.addItem(header);

            refreshCount++;
            if (refreshCount > 10000) {
                refreshCount = 0;
                isGatewayDetected = false;
                isPingReceived = false;
                try {
                    sendArp(networkIface, gatewayAddress);
                } catch (PcapNativeException e) {
                    e.printStackTrace();
                }
            }
        };

        pcapHandle = networkIface.openLive(SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIME_OUT);

        new Thread(() -> {
            try {
                pcapHandle.loop(COUNT, listener);
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (InterruptedException | NotOpenException e) {
                e.printStackTrace();
                // do nothing
            }
        }).start();

    }
    public void destroy() {
        if (isCapturing) {
            gateway = null;
            isCapturing = false;
            try {
                pcapHandle.breakLoop();
                pcapHandle.close();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }

    private void sendArp(PcapNetworkInterface networkIface, String gatewayAddress) throws PcapNativeException {
        Arp arp = new Arp();
        PcapHandle sendHandle = networkIface.openLive(SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIME_OUT);
        System.out.println("Arp");
        new Thread(() -> {
            arp.send(sendHandle, localhost, gatewayAddress);
            sendHandle.close();
        }).start();
    }

    private void receivedArpReply(String gatewayAddress, PacketHeader header, PcapNetworkInterface networkIface) throws PcapNativeException {
        if (header.getPacketType() == PacketType.RECEIVE
                && header.getSrcIpAddress().equals(gatewayAddress)) {

            isGatewayDetected = true;

            // TODO Subnet mask of IPv6
            gateway = new NetworkDevice(header.getSrcHardwareAddress(), header.getSrcIpAddress(), localhost.getIpV4SubnetMask());
            System.out.println("Arp Reply");
//            guiControllable.showGateway(gateway.getIpV4Address());
            Ping ping = new Ping(localhost);
            PcapHandle sendHandle = networkIface.openLive(SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIME_OUT);
            new Thread(() -> {
                ping.send(sendHandle, gateway, PING_DST);
                sendHandle.close();
            }).start();
        }
    }

    private void receivedPingReply(PacketHeader header, PcapNetworkInterface networkIface) throws PcapNativeException {
        if (header.getPacketType() == PacketType.RECEIVE
                && header.getSrcIpAddress().equals(PING_DST)) {

            isPingReceived = true;
//            guiControllable.showInternet();
            System.out.println("Ping Reply");
            PcapHandle sendHandle = networkIface.openLive(SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIME_OUT);
            new Thread(() -> {
                HostScanner scanner = new HostScanner();
                scanner.sendArpHostScan(sendHandle, localhost, 255);
                sendHandle.close();
            }).start();
        }
    }

}
