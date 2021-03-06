package com.assistanz.fogpanel

import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import java.util.logging.Level;
import java.util.logging.Logger;
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
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.QueryParam
import grails.converters.JSON
import com.assistanz.fogpanel.Config
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Path('/api/admin/template')
class TemplateApiResource {
    
    TemplateApiService templateApiService
    APIArgumentValidation apiArgumentValidation = new APIArgumentValidation()
    @GET
    @Path("/listTemplate")
    @Produces(MediaType.APPLICATION_JSON)
    String getTemplates(@QueryParam("baseOS") String baseOs, @QueryParam("appTemplate") String appTemplate, @QueryParam("page") String pageNo, 
        @QueryParam("recordPerPage") String recordPerPage) {
        try {            
            if(baseOs) {
                apiArgumentValidation.baseOsValidation(baseOs);
            }
            if(appTemplate) {
                apiArgumentValidation.appTemplateValidation(appTemplate);
            }
            if(pageNo) {                
                apiArgumentValidation.numberValidation(pageNo);
            }
            if(recordPerPage) {                
                apiArgumentValidation.numberValidation(recordPerPage);
            }
            
            templateApiService.getTemplates(baseOs, appTemplate, pageNo, recordPerPage) as JSON
        } catch (Exception ex) {
            [ex.message] as JSON
        } catch (RuntimeException ex) {
            [ex.message] as JSON
        }                            
    }
}
