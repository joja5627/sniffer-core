package com.network.core.pcap;
import com.liquid.packetanalyzer.main.Mode;
import com.liquid.packetanalyzer.pcap_file.PcapFileProcessor;
import com.network.core.service.PacketStorageServiceImpl;
import org.apache.commons.lang3.SerializationUtils;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.Objects;

import static com.liquid.packetanalyzer.main.Mode.BASIC_ANALYSIS;


public class PcapNetworkInterfaceWrapper {

    private PacketStorageServiceImpl packetStorageServiceImpl;
    private PcapNetworkInterface pcapNetworkInterface;
    private PcapHandle handler = null;
    private PcapFileProcessor processor = new PcapFileProcessor();

//    PcapFileProcessor processor = new PcapFileProcessor();


    public boolean supportsMonitorMode = true;
    public boolean supportsMonitorMode(){
        return supportsMonitorMode;
    }
    private final Logger logger = LoggerFactory.getLogger(PcapNetworkInterfaceWrapper.class);

    public PcapNetworkInterfaceWrapper(PcapNetworkInterface pcapNetworkInterface){
        this.pcapNetworkInterface = pcapNetworkInterface;
        packetStorageServiceImpl = new PacketStorageServiceImpl();

        try {
            this.handler = getPcapHandler(pcapNetworkInterface.getName());
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
    }


    public PcapHandle getPcapHandle(){
        return this.handler;
    }
    public List<PcapAddress> getAddresses() {
        return pcapNetworkInterface.getAddresses();
    }

    public String getName(){
        return pcapNetworkInterface.getName();
    }

    public String getDescription() {
        return pcapNetworkInterface.getDescription();
    }
    public static class PacketListenerTask implements Runnable {

        private PcapHandle handle;
        private PacketListener listener;

        public PacketListenerTask(PcapHandle handle, PacketListener listener) {
            this.handle = handle;
            this.listener = listener;
        }

        @Override
        public void run() {
            try {
                handle.loop(-1, listener);
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }

    }
    private PcapHandle getPcapHandler(String interfaceName) throws PcapNativeException {
        return new PcapHandle.Builder(interfaceName)
                .rfmon(true)
                .snaplen(65536)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(100)
                .bufferSize(5 * 1024 * 1024)
                .timestampPrecision(PcapHandle.TimestampPrecision.MICRO).build();
    }

    private void handlePacket(Packet packet){

        if(Objects.nonNull(handler)){
           ;
            processor.processPcapFile( SerializationUtils.clone(handler),BASIC_ANALYSIS);
        }


//        BASIC_ANALYSIS,
//                DETAILED_ANALYSIS,
//                POSSIBLE_ATTACKS_ANALYSIS
//        packetStorageServiceImpl.storePcap(handler,packet);

    }

    public PacketListenerTask buildPacketCaptureTask() throws PcapNativeException {
        return new PacketListenerTask(getPcapHandler(pcapNetworkInterface.getName()),
                (packet) -> {handler.getTimestamp();
            handlePacket(packet);
        });
    }

}
