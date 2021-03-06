package com.assistanz.cloud.cloudstack;

/**
 * 
 * @author Gowtham
 *
 */
public class CapacityResponse {
	
	/**
	 * the total capacity available
	 */
	String capacityTotal;
	
	/**
	 * the capacity currently in use
	 */
	String capacityUsed;
	
	/**
	 * the Cluster ID
	 */
	String clusterId;
	
	/**
	 * the Cluster name
	 */
	String clusterName;	
	
	/**
	 * the percentage of capacity currently in use
	 */
	String percentUsed;	
	
	/**
	 * the Pod ID
	 */
	String podId;
	
	/**
	 * the Pod name
	 */
	String podName;	
	
	/**
	 * the capacity type
	 */
	String capacityType;
	
	/**
	 * the Zone ID
	 */
	String zoneId;
	
	/**
	 * the Zone name
	 */
	String zoneName;

	public String getCapacityTotal() {
		return capacityTotal;
	}

	public void setCapacityTotal(String capacityTotal) {
		this.capacityTotal = capacityTotal;
	}

	public String getCapacityUsed() {
		return capacityUsed;
	}

	public void setCapacityUsed(String capacityUsed) {
		this.capacityUsed = capacityUsed;
	}

	public String getClusterId() {
		return clusterId;
	}

	public void setClusterId(String clusterId) {
		this.clusterId = clusterId;
	}

	public String getClusterName() {
		return clusterName;
	}

	public void setClusterName(String clusterName) {
		this.clusterName = clusterName;
	}

	public String getPercentUsed() {
		return percentUsed;
	}

	public void setPercentUsed(String percentUsed) {
		this.percentUsed = percentUsed;
	}

	public String getPodId() {
		return podId;
	}

	public void setPodId(String podId) {
		this.podId = podId;
	}

	public String getPodName() {
		return podName;
	}

	public void setPodName(String podName) {
		this.podName = podName;
	}

	public String getCapacityType() {
		return capacityType;
	}

	public void setCapacityType(String capacityType) {
		this.capacityType = capacityType;
	}

	public String getZoneId() {
		return zoneId;
	}

	public void setZoneId(String zoneId) {
		this.zoneId = zoneId;
	}

	public String getZoneName() {
		return zoneName;
	}

	public void setZoneName(String zoneName) {
		this.zoneName = zoneName;
	}	
	
	

}
