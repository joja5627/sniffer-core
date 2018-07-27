package com.network.core.config;


import com.network.core.service.PacketCaptureFolderImpl;

public class PacketCaptureFolderConfig {

    public PacketCaptureFolderImpl getMainPacketCaptureFolderImpl(){

        return new PacketCaptureFolderImpl("main");
    }


}
