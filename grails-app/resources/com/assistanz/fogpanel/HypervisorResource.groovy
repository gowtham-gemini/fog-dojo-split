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
import javax.ws.rs.DELETE
import javax.ws.rs.PathParam
import javax.ws.rs.core.Response
import javax.ws.rs.core.Request
import javax.ws.rs.QueryParam
import grails.converters.deep.JSON


@Path('/api/hypervisor')
class HypervisorResource {
    
    HypervisorService hypervisorService

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    String getHypervisorRepresentation() {
        'Hypervisor'
    }
    
    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    def get(@PathParam("id") String id) {
        try {
            hypervisorService.get(id) as JSON;
        } catch (ValidationException ex) {
                [ex] as JSON
        } catch (Exception ex){
                [ex] as JSON
        }
    }
}
