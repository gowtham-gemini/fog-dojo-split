package com.assistanz.fogpanel.auth

import com.assistanz.fogpanel.Account
import com.assistanz.fogpanel.AccountClosedException
import com.assistanz.fogpanel.CSAccountNotFound
import com.assistanz.fogpanel.IPLockedException
import com.assistanz.fogpanel.User
import org.springframework.context.ApplicationListener
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import com.assistanz.fogpanel.UserEvent
import com.assistanz.fogpanel.User
import com.assistanz.fogpanel.EventLogIpAddress
import java.util.Date
import grails.converters.deep.JSON
import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.plugin.springsecurity.userdetails.GrailsUserDetailsService
import grails.plugin.springsecurity.SpringSecurityUtils
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.authentication.BadCredentialsException
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import javax.servlet.http.HttpSession
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import com.assistanz.cloud.cloudstack.CloudStackServer;
import com.assistanz.cloud.cloudstack.login.CSLoginService;
import com.assistanz.cloud.cloudstack.login.LoginServiceResponse
import org.codehaus.groovy.grails.commons.ApplicationHolder
    
class CustomAuthService implements GrailsUserDetailsService {
    
    static final List NO_ROLES = [new GrantedAuthorityImpl(SpringSecurityUtils.NO_ROLE)]
 
    
    UserDetails loadUserByUsername(String username, boolean loadRoles) throws UsernameNotFoundException, AuthenticationException {
        return loadUserByUsername(username)
    }
    
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, AuthenticationException {
        GrailsWebRequest webUtils = WebUtils.retrieveGrailsWebRequest()
        def request = webUtils.getCurrentRequest()                                             
        User.withTransaction { status ->
            User user = User.findByUsername(username)
            if (!user) {
                throw new UsernameNotFoundException('User not found', username)
            } else {
                
                HttpSession session = request.getSession(false);
                String csLoginResponse = (String)session.getAttribute("csLoginResponse");
                String password = (String)session.getAttribute("password");
                
                println("after login");
                println(csLoginResponse);
                println(password);
                if(csLoginResponse != null && csLoginResponse != "" ) {
                    // Parse a JSON String
                    def csLoginResponseOb = JSON.parse(csLoginResponse); 
                    
                    println("csLoginResponseOb.loginresponse.userid"+csLoginResponseOb?.loginresponse?.userid);
                    println("user.uuid"+user?.uuid)
                    
                    // bye pass the check for admin alone
                    if(csLoginResponseOb?.loginresponse?.type != "1") {
                        
                        def csApiCheck = this.csApiCheckByUserNameAndPassword(username , password, 
                        csLoginResponseOb?.loginresponse?.userid);

                        //checking user's userid with csresponse's userid
                        if(csLoginResponseOb?.loginresponse?.userid != user?.uuid 
                            && csApiCheck) {
                            println("inside account not found");
                            throw new CSAccountNotFound("Account not found in cloudstack");
                        }
                    }
                    
                }
                
                def account = user.account
                if(account.status.name() == "CLOSED") {
                    throw new AccountClosedException('Account Closed')  
                } 
            }
            
           
            
            String ipAddress = getIPAddress(request)
            
            Date date = new Date()
            EventLogIpAddress.withTransaction {
                EventLogIpAddress eventLogIpAddress = EventLogIpAddress.findWhere(ipAddress:ipAddress,
                    user:User.findByUsername(username))
                    
                if(eventLogIpAddress && eventLogIpAddress.isLocked == true) {
                    throw new IPLockedException('Your IP locked')  
                }
                if (!eventLogIpAddress) {
                    eventLogIpAddress = new EventLogIpAddress()
                    eventLogIpAddress.ipAddress = ipAddress
                    eventLogIpAddress.failureCount = 0
                    eventLogIpAddress.successCount = 1
                    eventLogIpAddress.overAllCount = 1
                    eventLogIpAddress.overAllFailureCount = 0
                    eventLogIpAddress.isLocked = false
                    eventLogIpAddress.user = User.findByUsername(username)
                    eventLogIpAddress.save(flush: true)
                } else if(eventLogIpAddress) {
                    eventLogIpAddress.failureCount = eventLogIpAddress.failureCount
                    eventLogIpAddress.overAllFailureCount = eventLogIpAddress.overAllFailureCount
                    eventLogIpAddress.successCount = eventLogIpAddress.successCount + 1
                    eventLogIpAddress.overAllCount = eventLogIpAddress.successCount + eventLogIpAddress.overAllFailureCount
                    eventLogIpAddress.lockTime = null;
                    eventLogIpAddress.save(flush: true)
                }    
            }
            UserEvent.withTransaction {
                UserEvent userEvent = new UserEvent()
                userEvent.ipAddress = ipAddress
                userEvent.eventType = "login success"
                userEvent.date = date.toString()
                userEvent.failedCount = 0
                userEvent.user = User.findByUsername(username)
                userEvent.eventLogIpAddress = EventLogIpAddress.findWhere(ipAddress:ipAddress,
                    user:User.findByUsername(username))
                userEvent.save(flush: true)
                if (!userEvent.save()) {
                    userEvent.errors.allErrors.each { Console.print(it) }
                }
            }
            User.withTransaction {
                User eventuser = User.findByUsername(username)
                eventuser.failureCount = 0
                eventuser.lockTime = null
                eventuser.save(flush: true)
            }
            
            
            def authorities = user.authorities.collect {new GrantedAuthorityImpl(it.authority)}
             
            return new GrailsUser(user.username, user.password, user.enabled, !user.accountExpired,
                !user.passwordExpired, !user.accountLocked, authorities ?: NO_ROLES, user.id)
        }
    }
    
    
    private static final String[] HEADERS_TO_TRY = [ 
                "X-Forwarded-For", 
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR" ];
    
    def getIPAddress(request) {
                    
        for (String header : HEADERS_TO_TRY) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip;
            }
        }
        return request.getRemoteAddr();
        
    } 
        
    
    // background check with api using admin credentials
    def csApiCheckByUserNameAndPassword(String username, String password, String userid ) {
        
        println("inside api check");
        
        def cloudStackUrl =  ApplicationHolder.getApplication().config.cloudstack.api.url
        def cloudStackApiKey = ApplicationHolder.getApplication().config.cloudstack.api.key
        def cloudStackSecretKey = ApplicationHolder.getApplication().config.cloudstack.api.secret
        
        CloudStackServer server = new CloudStackServer(cloudStackUrl, cloudStackSecretKey, cloudStackApiKey)
        CSLoginService csLoginService = new CSLoginService(server);
        
        LoginServiceResponse loginResponse = csLoginService.login(username, password, null);
        
        def loginResponseJson = loginResponse as JSON;
        println("loginResponseJson "+loginResponseJson);
        
        if(loginResponse != null && loginResponse.getUserId() == userid)
        {
            
            return true;
            
        } else {
            
            return false;
        }
        
        
    }
    
}
