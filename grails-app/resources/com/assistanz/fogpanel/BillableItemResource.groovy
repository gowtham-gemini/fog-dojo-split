package com.assistanz.fogpanel

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import org.springframework.web.bind.annotation.RequestBody;
import javax.ws.rs.GET
import javax.ws.rs.POST;
import javax.ws.rs.Path
import javax.ws.rs.PUT
import javax.ws.rs.Produces
import javax.ws.rs.core.MediaType;
import com.assistanz.fogpanel.ComputingOffer
import javax.ws.rs.DELETE
import javax.ws.rs.PathParam
import javax.ws.rs.core.Response
import javax.ws.rs.core.Request
import javax.ws.rs.QueryParam
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import grails.converters.deep.JSON

@Path('/api/billableItem')
class BillableItemResource {
    
    BillableItemService billableItemService

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    String getBillableItemRepresentation() {
        try { 
            billableItemService.list()as JSON;
        } catch (Exception ex){
                [ex] as JSON
        }
    }
    
    
    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    String get(@PathParam("id") Long id) {
        try { 
            billableItemService.getBillableItem(id)as JSON;
        } catch (Exception ex){
                [ex] as JSON
        }
    }
    
    
    @PUT
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    def update(@RequestBody String requestBody) {
        try {
                        
            billableItemService.update(requestBody)as JSON
        } catch (ValidationException ex) {
                [ex] as JSON
        } catch (LicenseExpiredException ex) {
                [result: "licenseExpired", message: "License Expired! Contact Support"] as JSON
        } catch (NullPointerException ex){
                [ex] as JSON
        } catch (Exception ex){
                [ex] as JSON
        }
    }
    
}
