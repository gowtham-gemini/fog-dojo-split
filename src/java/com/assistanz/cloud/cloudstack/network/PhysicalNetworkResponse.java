/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.assistanz.cloud.cloudstack.network;

/**
 *
 * @author gowtham
 */
class PhysicalNetworkResponse {
    
     /**
     * the uuid of the physical network
     */
    private String physicalNetworkId;

    /**
     * Broadcast domain range of the physical network
     */
    private String physicalNetworkBroadcastDomainRange;

    /**
     * the domain id of the physical network owner
     */
    private String physicalNetworkDomainId;

    /**
     * isolation methods
     */
    private String isolationMethods;

    /**
     * name of the physical network
     */
    private String physicalNetworkName;

    /**
     * the speed of the physical network
     */
    private String physicalNetworkSpeed;

    /**
     * state of the physical network
     */
    private String physicalNetworkState;

    /**
     * comma separated tag
     */
    private String physicalNetworkTags;

    /**
     * the vlan of the physical network
     */
    private String physicalNetworkVlan;

    /**
     * zone id of the physical network
     */
    private String physicalNetworkZoneId;

    public String getPhysicalNetworkId() {
        return physicalNetworkId;
    }

    public void setPhysicalNetworkId(String physicalNetworkId) {
        this.physicalNetworkId = physicalNetworkId;
    }

    public String getPhysicalNetworkBroadcastDomainRange() {
        return physicalNetworkBroadcastDomainRange;
    }

    public void setPhysicalNetworkBroadcastDomainRange(
            String physicalNetworkBroadcastDomainRange) {
        this.physicalNetworkBroadcastDomainRange = physicalNetworkBroadcastDomainRange;
    }

    public String getPhysicalNetworkDomainId() {
        return physicalNetworkDomainId;
    }

    public void setPhysicalNetworkDomainId(String physicalNetworkDomainId) {
        this.physicalNetworkDomainId = physicalNetworkDomainId;
    }

    public String getIsolationMethods() {
        return isolationMethods;
    }

    public void setIsolationMethods(String isolationMethods) {
        this.isolationMethods = isolationMethods;
    }

    public String getPhysicalNetworkName() {
        return physicalNetworkName;
    }

    public void setPhysicalNetworkName(String physicalNetworkName) {
        this.physicalNetworkName = physicalNetworkName;
    }

    public String getPhysicalNetworkSpeed() {
        return physicalNetworkSpeed;
    }

    public void setPhysicalNetworkSpeed(String physicalNetworkSpeed) {
        this.physicalNetworkSpeed = physicalNetworkSpeed;
    }

    public String getPhysicalNetworkState() {
        return physicalNetworkState;
    }

    public void setPhysicalNetworkState(String physicalNetworkState) {
        this.physicalNetworkState = physicalNetworkState;
    }

    public String getPhysicalNetworkTags() {
        return physicalNetworkTags;
    }

    public void setPhysicalNetworkTags(String physicalNetworkTags) {
        this.physicalNetworkTags = physicalNetworkTags;
    }

    public String getPhysicalNetworkVlan() {
        return physicalNetworkVlan;
    }

    public void setPhysicalNetworkVlan(String physicalNetworkVlan) {
        this.physicalNetworkVlan = physicalNetworkVlan;
    }

    public String getPhysicalNetworkZoneId() {
        return physicalNetworkZoneId;
    }

    public void setPhysicalNetworkZoneId(String physicalNetworkZoneId) {
        this.physicalNetworkZoneId = physicalNetworkZoneId;
    }
    
    
}
