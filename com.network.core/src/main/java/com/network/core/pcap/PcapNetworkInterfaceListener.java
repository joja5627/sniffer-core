/**
 * Copyright (c) 2010-2017 by the respective copyright holders.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.network.core.pcap;

import org.pcap4j.core.PcapNetworkInterface;

public interface PcapNetworkInterfaceListener{

    /**
     * This method is called whenever a new {@link PcapNetworkInterfaceWrapper}
     * is added.
     *
     * @param newNetworkInterface
     *            The added networkInterface
     */
    public void onPcapNetworkInterfaceAdded(PcapNetworkInterfaceWrapper newNetworkInterface);

    /**
     * This method is called whenever a {@link PcapNetworkInterfaceWrapper} is
     * removed.
     *
     * @param removedNetworkInterface
     *            The removed networkInterface
     */
    public void onPcapNetworkInterfaceRemoved(PcapNetworkInterfaceWrapper removedNetworkInterface);
}
