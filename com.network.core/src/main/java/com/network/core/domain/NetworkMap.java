package com.network.core.domain;



import com.network.core.service.NetworkDevice;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

public class NetworkMap {

    private static final int QUEUE_MAX = 1000;
    private static final int IMAGE_SIZE = 72;
    private static final String INTERNET = "INTERNET";

    private int line, internetX, internetY, gatewayX, gatewayY;
    private ConcurrentLinkedQueue<PacketCircle> packetQueue;
    private ConcurrentHashMap<String, NetworkObject> objectMap;
    private CopyOnWriteArrayList<NetworkLine> lineList;
    private List<String> localNetworkHostsList;
    private String gatewayIpAddress;

    private PacketHeader lastPacket;

    public NetworkMap() {}


    public void showLocalhost(NetworkDevice device) {
        // TODO show IPv6 address of localhost
        //if (device.getIpV6Address() != null && !device.getIpV6Address().equals("")) {
        //    localhostIpAddress = device.getIpV6Address();
        //} else {
        detectHostsInNetwork(device.getIpV4Address(), device.getHardwareAddress());
        //}
    }

    public void showGateway(String defaultGateway) {
        if (defaultGateway != null && !defaultGateway.equals("")) {
            gatewayIpAddress = defaultGateway;
            objectMap.put(defaultGateway, new NetworkObject( defaultGateway, gatewayX, gatewayY));
        }
        createNetworkLine();
    }

    public void showInternet() {
        objectMap.put(INTERNET, new NetworkObject( INTERNET, internetX, internetY));
        createNetworkLine();
    }

    public void addPacket(PacketHeader header) {
        if (packetQueue.size() < QUEUE_MAX && !isSameHeader(header)) {
            lastPacket = header;
            NetworkObject src, gateway, dst;
            src = objectMap.get(header.getSrcIpAddress());
            gateway = objectMap.get(gatewayIpAddress);
            dst = objectMap.get(header.getDstIpAddress());
            if (src == null || dst == null) {
                if (header.isDstAsBroadcast()) {
                    dst = gateway;
                } else {
                    switch (header.getPacketType()) {
                        case RECEIVE:
                            if (header.isSrcAsSameSubnet()) {
                                // add new host to objectMap
                                detectHostsInNetwork(header.getSrcIpAddress(), header.getSrcHardwareAddress());
                            } else {
                                src = objectMap.get(INTERNET);
                            }
                            break;

                        case SEND:
                            if (header.isDstAsSameSubnet()) {
                                dst = gateway;
                            } else {
                                dst = objectMap.get(INTERNET);
                            }
                            break;

                        default:
                            if (header.isSrcAsSameSubnet()) {
                                if (src == null) {
                                    detectHostsInNetwork(header.getSrcIpAddress(), header.getSrcHardwareAddress());
                                } else {
                                    dst = objectMap.get(INTERNET);
                                }
                            } else if (header.isDstAsSameSubnet()) {
                                if (dst == null) {
                                    detectHostsInNetwork(header.getDstIpAddress(), header.getDstHardwareAddress());
                                } else {
                                    src = objectMap.get(INTERNET);
                                }
                            }
                            break;

                    }
                }
            }
            if (src != null && dst != null) {
                PacketCircle circle = new PacketCircle(this, src, gateway, dst, header);
                packetQueue.offer(circle);
            }
        }
    }

    public void refresh() {
        objectMap.clear();
        localNetworkHostsList.clear();
    }

    void sendBroadcast(PacketHeader header) {
        new Thread(() -> {
            for (String address : localNetworkHostsList) {
                if (address.equals(header.getSrcIpAddress())) {
                    continue;
                }
                NetworkObject gateway = objectMap.get(gatewayIpAddress);
                NetworkObject dst = objectMap.get(address);
                PacketCircle circle = new PacketCircle(this, gateway, gateway, dst, header);
                packetQueue.offer(circle);
            }
        }).start();
    }


    private void detectHostsInNetwork(String ipAddress, String hardwareAddress) {
        if ("00:00:00:00:00:00".equals(hardwareAddress)) {
            return;
        }

        localNetworkHostsList.add(ipAddress);

        NetworkObject host = new NetworkObject(ipAddress, gatewayX, gatewayY + line);
        objectMap.put(ipAddress, host);

        int count = localNetworkHostsList.size() - 1;

        if (count > 0) {
            int i = 0;
            for (String localNetworkHost : localNetworkHostsList) {
                NetworkObject object = objectMap.get(localNetworkHost);

                double rad = (1.0d + ((double) i / count)) * Math.PI;
                int x = (int) (Math.cos(rad) * line + gatewayX);
                int y = (int) (Math.sin(rad) * -1 * line + gatewayY);

                object.setX(x);
                object.setY(y);

                i++;
            }
        }

        createNetworkLine();
    }

    private void createNetworkLine() {
        lineList.clear();
        if (objectMap.get(INTERNET) != null) {
            lineList.add(new NetworkLine(objectMap.get(gatewayIpAddress), objectMap.get(INTERNET)));
        }
        if (gatewayIpAddress != null && objectMap.get(gatewayIpAddress) != null) {
            for (String localNetworkHost : localNetworkHostsList) {
                lineList.add(new NetworkLine(objectMap.get(gatewayIpAddress), objectMap.get(localNetworkHost)));
            }
        }
    }

    private boolean isSameHeader(PacketHeader item) {
        if (lastPacket != null) {
            return lastPacket.getProtocol() == item.getProtocol()
                    && lastPacket.getSrcIpAddress().equals(item.getSrcIpAddress())
                    && lastPacket.getDstIpAddress().equals(item.getDstIpAddress())
                    && lastPacket.getSrcPort() == item.getSrcPort()
                    && lastPacket.getDstPort() == item.getDstPort();
        } else {
            return false;
        }
    }
}
