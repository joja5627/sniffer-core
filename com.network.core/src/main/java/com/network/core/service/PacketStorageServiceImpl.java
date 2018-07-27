package com.network.core.service;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class PacketStorageServiceImpl implements PacketStorageService {

    private final Logger logger = LoggerFactory.getLogger(PacketStorageServiceImpl.class);

    final String pcapFileBase = "capture";

    private int storedPackets = 0;

//    private static final String TMP_DIR_PROP
//            = PacketStorageServiceImpl.class.getName() + ".packet-capture-dir";
    private String packetCaptureFolderImpl;

    public PacketStorageServiceImpl(){
        Properties props = System.getProperties();
        packetCaptureFolderImpl = Paths.get(System.getProperty("user.dir"),"data").toAbsolutePath().toString();
        logger.info(packetCaptureFolderImpl);
        File tmpDir = new File(packetCaptureFolderImpl);
        if (!tmpDir.exists()) {
            if (!tmpDir.mkdirs()) {
                try {
                    throw new IOException("Failed to make a test diectory: " + packetCaptureFolderImpl);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private String getNewPacketPath(int packetCount){

        Path newPath = Paths.get(
                String.format("%s/%s.pcap", packetCaptureFolderImpl,
                    pcapFileBase + String.valueOf(packetCount)));
        logger.info(newPath.toString());
            if(!Files.exists(newPath)){
                try {
                    Files.createFile(newPath);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        return newPath.toString();
    }

    public boolean storePcap(PcapHandle handle, Packet packet){
        PcapDumper dumper;

            try {
                dumper = handle.dumpOpen(getNewPacketPath(storedPackets));
                storedPackets+=1;
                dumper.dump(packet, handle.getTimestamp());
                handle.close();
                dumper.close();

            } catch (PcapNativeException e) {
                e.printStackTrace();
                return false;
            } catch (NotOpenException e) {
                e.printStackTrace();
                return false;
            }
        dumper.close();
        return true;
    }



    }

