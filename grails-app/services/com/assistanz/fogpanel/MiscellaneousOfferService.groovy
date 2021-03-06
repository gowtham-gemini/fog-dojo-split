package com.assistanz.fogpanel

import grails.converters.JSON
import org.apache.commons.logging.LogFactory;

class MiscellaneousOfferService {
    
    LicenseValidationService licenseValidationService
    def springSecurityService
    private static final log = LogFactory.getLog(this)

    def list(String clusterReferenceId, String miscellaneousOfferId) {
        
        if((clusterReferenceId == "null" || clusterReferenceId == null) && (miscellaneousOfferId == "null" || miscellaneousOfferId == null)) {
            return MiscellaneousOffer.findAll();   
        } else if((clusterReferenceId != "null" || clusterReferenceId != null) && (miscellaneousOfferId != "null" || miscellaneousOfferId != null)) {
            def miscelOffer =  MiscellaneousOfferZoneCost.findAllWhere(miscellaneousOffer: MiscellaneousOffer.get(miscellaneousOfferId), cluster: Cluster.findByClusterReferenceId(clusterReferenceId));              
            return miscelOffer
        } 
    }
    
    def getMisc (String zoneReferenceId, String miscellaneousOfferId) {
        if((zoneReferenceId == "null" || zoneReferenceId == null) && (miscellaneousOfferId == "null" || miscellaneousOfferId == null)) {
            return MiscellaneousOffer.findAll();   
        } else if((zoneReferenceId != "null" || zoneReferenceId != null) && (miscellaneousOfferId != "null" || miscellaneousOfferId != null)) {
            def miscelOffer =  MiscellaneousOfferZoneCost.findAllWhere(miscellaneousOffer: MiscellaneousOffer.get(miscellaneousOfferId), zone: Zone.findByReferenceZoneId(zoneReferenceId));              
            return miscelOffer
        }
    }
    
    def update(String requestBody) {
        
        try {
            
            licenseValidationService.authorizeAction(FogPanelService.OFFERING_UPDATE)
            
            def user = springSecurityService.currentUser
            def role = springSecurityService.getPrincipal().getAuthorities()      
            
            // convert string to json object
            def requestData = JSON.parse(requestBody)

            MiscellaneousOfferZoneCost existsMiscellaneousOfferZoneCost = 
                        MiscellaneousOfferZoneCost.findWhere(miscellaneousOffer: MiscellaneousOffer.get(requestData.id), 
                        cluster: Cluster.findByClusterReferenceId(requestData.clusterReferenceId));
                    
            
            def oldCost
            
            def miscellaneousOffer =  MiscellaneousOffer.get(requestData.id);   
            
            if(existsMiscellaneousOfferZoneCost) {
                
                oldCost = existsMiscellaneousOfferZoneCost.cost

//                for(int i = 0; i < requestData.zoneCosts.length(); i++){
//
//                    Double zoneCost = new Double(requestData.zoneCosts[i].cost);
//                    if(zoneCost == 0.0){
//                        throw new NullPointerException("cost cannot be zero");
//                    }
//                }
//                existsMiscellaneousOfferZoneCost.delete(flush: true);

                for(int i = 0; i < requestData.zoneCosts.length(); i++) {

                    Double cost = new Double(requestData.zoneCosts[i].cost);
                    if(cost == 0.0){
                        throw new NullPointerException("cost cannot be zero");
                    }
                    
                    existsMiscellaneousOfferZoneCost.cost = cost
                    existsMiscellaneousOfferZoneCost.save(flush: true)
                }
            }  else {
                
                for(int i = 0; i < requestData.zoneCosts.length(); i++) {

                    Double cost = new Double(requestData.zoneCosts[i].cost);
                    if(cost == 0.0){
                        throw new NullPointerException("cost cannot be zero");
                    }
                    miscellaneousOffer.addToMiscellaneousOfferZoneCosts(new MiscellaneousOfferZoneCost(
                        MiscellaneousOffer : miscellaneousOffer.get(requestData.id),
                        zone:Zone.get(requestData.zoneCosts[i].zoneId), 
                        cluster:Cluster.findByClusterReferenceId(requestData.clusterReferenceId),
                        pod:Pod.findByPodReferenceId(requestData.podReferenceId),
                        cost: cost))            
                }
                
            }

            //save MiscellaneousOffer
            miscellaneousOffer.save(flush: true);
                        
            def newCost = MiscellaneousOfferZoneCost.findWhere(miscellaneousOffer: miscellaneousOffer, 
                        cluster: Cluster.findByClusterReferenceId(requestData.clusterReferenceId));
            
            if(oldCost != newCost.cost) {
            
                def serviceCostChangeLog = new ServiceCostChangeLog()
                serviceCostChangeLog.serviceName = ServiceName.valueOf("MISC_OFFER")
                serviceCostChangeLog.oldCost = oldCost
                serviceCostChangeLog.changedDate = new Date()

                serviceCostChangeLog.user = user
                serviceCostChangeLog.account = user.account

                serviceCostChangeLog.newCost = newCost.cost
                serviceCostChangeLog.miscellaneousOfferZoneCost = newCost;
                serviceCostChangeLog.save(flush: true)  
            
            }
            log.info("Updated Miscellaneous for : ${miscellaneousOffer.name}, successfully")   
            if (miscellaneousOffer.hasErrors()) {
                throw new ValidationException(miscellaneousOffer.errors.allErrors);
            }
            
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
            throw ex;
        }
    }
}
