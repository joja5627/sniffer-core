package com.network.core.service;

import org.pcap4j.util.MacAddress;

/**
 * Created by ddubson on 3/5/17.
 */
public interface ArpQuery {
    MacAddress arp(String nif, String srcIpAddr, String dstIpAddress);
}
