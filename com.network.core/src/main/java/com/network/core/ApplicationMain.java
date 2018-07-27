package com.network.core;


import com.network.core.pcap.NetworkDiscoveryService;
import org.pcap4j.core.PcapNativeException;



public class ApplicationMain {

    public static void main(String[] args) {
//        PcapFileSummary processPcapFile;

        try {
            NetworkDiscoveryService networkDiscoveryService = new NetworkDiscoveryService();
            networkDiscoveryService.start();
        } catch (PcapNativeException e) {
            e.printStackTrace();
            System.exit(1);
        }

//        Runtime.getRuntime().addShutdownHook(new Thread(networkDiscoveryService.stopAllWrappers()));



    }
}


