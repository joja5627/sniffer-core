package com.network.core.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PacketCaptureFolderImpl implements PacketCaptureFolder {

    private Path folderPath;
    public String getPath(){
        return folderPath.toString();
    }
    public PacketCaptureFolderImpl(String folderLocation){
        folderPath = Paths.get("src",folderLocation,"data");
        //if directory exists?
        if (!Files.exists(folderPath)) {
            try {
                Files.createDirectories(folderPath);
            } catch (IOException e) {
                //fail to create directory
                e.printStackTrace();
            }
        }

    };

}