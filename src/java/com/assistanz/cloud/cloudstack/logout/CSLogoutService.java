package com.assistanz.cloud.cloudstack.logout;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.apache.commons.httpclient.NameValuePair;
import com.assistanz.cloud.cloudstack.CloudStackServer;
import com.assistanz.cloud.cloudstack.logout.LogoutServiceResponse;
import java.util.LinkedList;



/**
 * 
 * @author Gowtham
 *
 */
public class CSLogoutService {
	
	private CloudStackServer server;
	
	public CSLogoutService(CloudStackServer server) {
		this.server = server;
	}
	
	/**
	 * Logs out the user
	 * 
	 * @return
         * @throws java.lang.Exception
	 */
	public LogoutServiceResponse logout() throws Exception {
            
            LinkedList<NameValuePair> arguments = 
                server.getDefaultQuery("logout", null);
       		
        Document responseDocument = server.makeRequest(arguments);
		
        return getLogoutServiceResponse(responseDocument);
	}
	
	/**
	 * Converts XML document into LogoutServiceResponse object
	 * 
	 * @param doc
	 * @return
	 */
	private LogoutServiceResponse getLogoutServiceResponse(Document doc) {
		LogoutServiceResponse response = new LogoutServiceResponse();
				
		// get description from XML and set success if the logout action succeeded
        NodeList list = doc.getElementsByTagName("description");
        if (list.getLength() > 0) {
            Node node = list.item(0);
            response.setDescription(node.getTextContent());
        }
        
		return response;
	}
}