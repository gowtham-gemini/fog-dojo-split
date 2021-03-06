<!DOCTYPE html>
<html lang="${lang}">
    <head>
      <title>${orgName} <g:message code="common.admin"/></title>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">  
      <r:layoutResources/> 
      <link rel="stylesheet" href="${resource(dir: 'css/theme/fog-classic/', file: 'fog-classic.css')}"  media="screen" type="text/css" />
      <g:if test="${GrailsUtil.isDevelopmentEnv()}" >
          <script>
           var dojoConfig = {
              async: 1,
              ioPublish: true,
              cacheBust: 1,
              parseOnLoad: false,
              tlmSiblingOfDojo: true,
              locale: '${lang}'
            };
          </script>
          <!--<script type="text/javascript" src="${resource(dir: 'js/dojo-1.8/dojo')}/dojo.js" data-dojo-config="async: true, parseOnLoad:false"></script>-->
          <script type="text/javascript" src="//192.168.1.153/UIComponents/public_html/js/lib/dojo/dojo/dojo.js" data-dojo-config="async: true, parseOnLoad:false"></script>
      </g:if >
      <g:else >
          <script>
           var dojoConfig = {
              async: 1,
              ioPublish: true,
              cacheBust: 0,
              parseOnLoad: false,
              tlmSiblingOfDojo: true,
              locale: '${lang}', 
              packages: [
                { name: "bootstrap", location: "http://dev.dojobootstrap.com/2x" },
                { name: "experimental", location: "http://dev.dojobootstrap.com/2x/experimental" },
              ]
            };
          </script>
          <script type="text/javascript" src="${resource(dir: 'js/dojo-1.8/release/dojo/dojo')}/dojo.js"></script>
          <script type="text/javascript" src="${resource(dir: 'js/dojo-1.8/release/dojo/dojo')}/dojo-x-build.js"></script>
      </g:else>
      <script type="text/javascript" src="${resource(dir: 'js')}/core.js" ></script>
      <script type="text/javascript" src="${resource(dir: 'js')}/jquery-1.9.1.min.js" ></script>
      <script>      
      core.setConfig({
          baseURL: "${baseUrl}",
          homepage: "${homepage}",
          context: "${contextPath}"
        });     
        core.setCurrency("${currency}");    
      </script> 
    </head>
    <body class="fog-classic">  
      <div class="row-fluid">
        <div class="loader" id="adminLoader">
          <div class="loader-cont">
          <div> 
            <g:if test="${logoUrl == ''}">                  
                <img height="49" width="133"  src="${resource(dir: 'images', file: 'fog_logo.png')}" class="logo fogPanelLogo"/>                   
            </g:if>
            <g:else>                  
                <img height="49" width="133"  src="${logoUrl}" class="logo fogPanelLogo" />                
            </g:else>
            <img src="${resource(dir: 'images')}/vmload.gif" alt="<g:message code="common.progress"/>" height="9" width="100">
          </div>
          <div>
            <p> <g:message code="common.loadingPanel"/>...</p>
          </div>         
        </div>
        </div>
      </div> 
      <div class="navbar navbar-inverse">
        <div data-dojo-type="FogPanel.Navigator" id="templateNavigator">     
          <div class="logo_wrapper">     
          <a class="brand" href="#/admin/dashboard">            
                <g:if test="${logoUrl == ''}">                   
                    <img src="${resource(dir: 'images', file: 'fog_logo.png')}" class="fogPanelLogo" />                    
                </g:if>
                <g:else>                 
                    <img src="${logoUrl}" class="fogPanelLogo" />                
                </g:else>               
          </a>        
          <div class="powered">Powered by FogPanel</div>
        </div>

          <div data-dojo-type="dijit.Toolbar" class="nav pull-right"> 
            <div data-dojo-type="dijit.form.DropDownButton" data-dojo-props="showLabel:true" class="notification-dropdown hidden-phone dashboardContent" title="<g:message code="stat.alerts"/>">
              <a href="#" class="trigger">
                <i class="icon-warning-sign"></i>
                <span class="count" id="cloudUsageStatusCount">0</span>
              </a>
              <div data-dojo-type="dijit.TooltipDialog" class="pop-dialog" onclick="dijit.popup.close(this);">      
                  <div id="cloudUsageNotificationDiv"></div>
              </div>
            </div>
            <div data-dojo-type="dijit.form.DropDownButton" data-dojo-props="showLabel:true" class="notification-dropdown hidden-phone dashboardContent" title="<g:message code="common.ticketNotification"/>">
                <a href="#" class="trigger" >
                  <i class="icon-bell-alt"></i>
                  <span class="count" id="ticketCount">0</span>
                </a>
                <div data-dojo-type="dijit.TooltipDialog" class="pop-dialog" onclick="dijit.popup.close(this);">
                  <div id="adminTicketNotification"></div>
                </div>
            </div>

            <div data-dojo-type="dijit.form.DropDownButton" title="<g:message code="common.settings"/>" data-dojo-props="showLabel:false, iconClass: 'icon-cog'" class="settings hidden-phone dashboardContent">  
                <div data-dojo-type="dijit.TooltipDialog" id="adminSettingsDropdown" class="" style="">            
                <a href="#/admin/settings/general" class="customWidth" onclick="DashboardWizard.closeDialogue();"><g:message code="menu.admin.configuration"/></a>              
              </div>
            </div>   

            <g:link controller='logout' class="icon-share-alt" title="${message(code:'common.logout')}"></g:link>
              </div>
          </div>
        </div>
      <div data-dojo-type="FogPanel.VerticalMenuBar" id="verticalMenu">      
          <ul class="dashboard-menu">
              <li>         
                  <a href="#/admin/dashboard" class="mainMenu singleMenu"><i class="icon-home"></i><span><g:message code="menu.admin.home"/></span></a>
              </li> 
              <li>
                  <a href="#/admin/account" class="mainMenu singleMenu"><span><i class="icon-group"></i><g:message code="menu.admin.clients"/></span></a>
              </li>
              <li id="cloudMenu">
                  <a href="#/admin/infrastructure/cloud" class="mainMenu dropdown-toggle">
                      <span><i class="icon-cloud"></i><g:message code="menu.admin.cloud"/></span>
                      <i class="icon-chevron-down"></i>
                  </a>
                      <ul class="submenu">
                          <li><a href="#/admin/infrastructure"><g:message code="menu.admin.cloud.infrastructure"/></a></li>
                          <li><a href="#/admin/firewall"><g:message code="menu.admin.cloud.firewall"/></a></li>
                          <li><a href="#/admin/resourceMonitoring"><g:message code="menu.admin.cloud.resourceUsage"/></a></li>     
                          <li><a href="#/admin/dashboard/maintainance"><g:message code="menu.admin.cloud.maintenance"/></a></li>
                          <li><a href="#/admin/vpc/list"><g:message code="common.vpc"/></a></li>
                      </ul>
              </li>        
              <li id="serviceMenu">
                  <a class="mainMenu dropdown-toggle" href="#/admin/computation/services">
                      <i class="iconfgs-menu_service_icon"></i>
                      <span><g:message code="menu.admin.services"/></span>
                      <i class="icon-chevron-down"></i>
                  </a>
                  <ul class="submenu">            
                      <li><a href="#/admin/computation/list"><g:message code="menu.admin.services.computation"/></a></li>
                      <li><a href="#/admin/disk/list"><g:message code="menu.admin.services.storage"/></a></li>
                      <li><a href="#/admin/miscellaneous/bandwidth"><g:message code="menu.admin.services.misc"/></a></li>  
                      <li><a href="#/admin/template"><g:message code="menu.admin.services.templateStore"/></a></li>
                      <li><a href="#/admin/networkOffer"><g:message code="menu.admin.services.networkoffer"/></a></li>
                  </ul>
              </li>
              <li>
                  <a class="mainMenu dropdown-toggle" href="#/admin/settings">
                      <i class="icon-cog"></i>
                      <span><g:message code="menu.admin.configuration"/></span>
                      <i class="icon-chevron-down"></i>
                  </a>
                  <ul class="submenu">            
                      <li><a href="#/admin/settings/general"><g:message code="menu.admin.configuration.general"/></a></li>
                      <li><a href="#/admin/settings/billing"><g:message code="menu.admin.configuration.billing"/></a></li>
                      <li><a href="#/admin/settings/cloudStack"><g:message code="menu.admin.configuration.cloudStack"/></a></li>
                  </ul>
              </li>
              <li>
                  <a class="mainMenu dropdown-toggle" href="#/admin/billing">
                      <i class="icon-shopping-cart"></i>
                      <span><g:message code="menu.admin.billing"/></span>
                      <i class="icon-chevron-down"></i>
                  </a>
                  <ul class="submenu">            
                      <li><a href="#/admin/billing/invoice"><g:message code="menu.admin.billing.invoice"/></a></li>
                      <li><a href="#/admin/billing/payment"><g:message code="menu.admin.billing.payments"/></a></li>
                      <li><a href="#/admin/billing/recurringItem"><g:message code="menu.admin.billing.recurringItems"/></a></li>  
                      <li><a href="#/admin/billing/serviceCostChange"><g:message code="common.serviceCostChange"/></a></li>  
                  </ul>
              </li>           
              <li>
                  <a href="#/admin/support/tickets" class="mainMenu singleMenu">
                    <i class="icon-credit-card"></i>
                    <span><g:message code="menu.admin.tickets"/></span>                
                  </a>              
              </li>
            <li>
                <a class="mainMenu dropdown-toggle" href="#/admin/reports">
                    <i class="icon-th-large"></i>
                    <span><g:message code="menu.admin.report"/></span>
                    <i class="icon-chevron-down"></i>
                </a>
                <ul class="submenu">
                    <li><a href="#/admin/reports/signUp"><g:message code="menu.admin.report.signUpReport"/></a></li>
                    <li><a href="#/admin/reports/billableItem"><g:message code="menu.admin.report.billableItem"/></a></li>
                    <li><a href="#/admin/reports/paymentReport"><g:message code="menu.admin.report.paymentReport"/></a></li>
                    <li><a href="#/admin/reports/creditLimitReport"><g:message code="menu.admin.report.creditLimitReport"/></a></li>
                    <li><a href="#/admin/reports/pendingPaymentReport"><g:message code="menu.admin.report.paymentPending"/></a></li>
                    <li><a href="#/admin/reports/clientUsage"><g:message code="menu.admin.report.clientUsage"/></a></li>
                </ul>
            </li>
            <li>
                <a class="mainMenu dropdown-toggle" href="#/admin/activity">
                    <i class="icon-comments"></i>
                    <span><g:message code="menu.admin.activity"/></span>            
                </a> 
                <ul class="submenu"></ul>
            </li>     
      </ul>     
    </div>
    <div class="content" id="contentArea">
                  <!--<div class="skins-nav">
                    <a href="#" class="skin first_nav selected">
                        <span class="icon"></span><span class="text">Default</span>
                    </a>
                    <a href="#" class="skin second_nav" data-file="css/skins/dark.css">
                        <span class="icon"></span><span class="text">Dark skin</span>
                    </a>
              </div>-->

          <div id="content" class="container-fluid"></div>
    </div>
    <div id="templateArea"></div>
    <div id="screen-loader"></div>
    <div data-dojo-type="dojox.widget.Toaster" data-dojo-props="positionDirection:'tr-left', duration:4000" id="appToaster"></div>
    <script type="text/javascript" src="${resource(dir: 'js')}/theme.js" ></script>
    </body>
</html>
