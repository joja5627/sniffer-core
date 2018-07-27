package com.network.core.pcap;
import com.google.common.collect.Sets;
import org.pcap4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class NetworkDiscoveryService extends Thread {

    private final Logger logger = LoggerFactory.getLogger(NetworkDiscoveryService.class);

    private Set<PcapNetworkInterfaceWrapper> initiallyWrappedInterfaces;

    protected static final int  CORE_COUNT = Runtime.getRuntime().availableProcessors();

    protected static final int DEFAULT_THREAD_POOL_SIZE = CORE_COUNT - 2;

    ExecutorService networkDiscoveryExecutorService = Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE);

//
//    @Override
//    public void run() {
//
//    }
//
//    private class stopWrappersRunnable  implements Runnable {
//        public void run(Set<PcapNetworkInterfaceWrapper> initiallyWrappedInterfaces) throws NotOpenException {
//            for (PcapNetworkInterfaceWrapper wrapper : initiallyWrappedInterfaces) {
////                stopPacketCapture(wrapper);
//            }
//        }
//        stopWrappersRunnable(initiallyWrappedInterfaces){
//        }
//    }
//
//        @Override
//        public void run() {
//
//        }
//    }
//    public stopWrappersRunnable buildstopWrappersRunnable(){
//        return new stopWrappersRunnable(initiallyWrappedInterfaces -> {
////                    handler.getTimestamp();
////                    System.out.println(packet.toString());
//                });




    private Set<PcapNetworkInterfaceWrapper> pcapNetworkInterfaces = new CopyOnWriteArraySet<>();

    private Set<PcapNetworkInterfaceWrapper> determineBoundNetworkInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs()
                .stream()
                .map(PcapNetworkInterfaceWrapper::new)
                .collect(Collectors.toSet());
        }


    public NetworkDiscoveryService() throws PcapNativeException {
        initiallyWrappedInterfaces = determineBoundNetworkInterfaces();
        initiallyWrappedInterfaces.add(new PcapNetworkInterfaceWrapper(Pcaps.getDevByName("en0")));


        for(PcapNetworkInterfaceWrapper pcapNetworkInterfaceWrapper:initiallyWrappedInterfaces){
            try{
                startPacketCapture(pcapNetworkInterfaceWrapper);
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    private void startPacketCapture(PcapNetworkInterfaceWrapper wrapper){
        try {
            networkDiscoveryExecutorService.execute(wrapper.buildPacketCaptureTask());
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
    }
    private void stopPacketCapture(PcapNetworkInterfaceWrapper wrapper) throws NotOpenException {
        wrapper.getPcapHandle().breakLoop();
        wrapper.getPcapHandle().close();
    }

    private static boolean isAmazonVendor(String macAddress) {
        String vendorPrefix = macAddress.substring(0, 8).toUpperCase();
        return VENDOR_PREFIXES.contains(vendorPrefix);
    }
    public static Set<String> getVendorPrefixes() {
        return VENDOR_PREFIXES;
    }



    private static final Set<String> VENDOR_PREFIXES = Sets.newHashSet(
            "F0:D2:F1",
            "88:71:E5",
            "FC:A1:83",
            "F0:27:2D",
            "74:C2:46",
            "68:37:E9",
            "78:E1:03",
            "38:F7:3D",
            "50:DC:E7",
            "A0:02:DC",
            "0C:47:C9",
            "74:75:48",
            "AC:63:BE",
            "FC:A6:67",
            "18:74:2E",
            "00:FC:8B",
            "FC:65:DE",
            "6C:56:97",
            "44:65:0D",
            "50:F5:DA",
            "68:54:FD",
            "40:B4:CD",
            "84:D6:D0",
            "34:D2:70",
            "B4:7C:9C"
    );



}
