<div class="row-fluid">
  <div class="span12 breadcrumbs">
    <ul>
      <li><a href="#/admin/dashboard"><i class="icon-home"></i></a></li> 
      <li>/</li>
      <li><a href="#/admin/computation/services" onclick="ServiceConfig.openTab()"><g:message code="menu.admin.services" /></a></li>
      <li>/</li>
      <li><a href="#/admin/miscellaneous"><g:message code="menu.admin.services.misc" /></a></li> 
      <li>/</li>
      <li><g:message code="common.bandwidth" /></li>
    </ul>
  </div>
</div>
<div class="row-fluid">   
  <ul class="nav nav-tabs span12">
    <li class="active">
      <a href="#/admin/miscellaneous/bandwidth"><g:message code="common.bandwidth" /></a>
    </li>
    <li>
      <a href="#/admin/miscellaneous/snapshot"><g:message code="menu.service.snapshot" /></a>
    </li> 
    <li>
      <a href="#/admin/miscellaneous/ipCost"><g:message code="common.ipCost"/></a>
    </li>
    <li>
     <a href="#/admin/miscellaneous/vmSnapCost"><g:message code="common.snapshot.VMSnapshot" /></a>
    </li>
    <li>
     <a href="#/admin/miscellaneous/loadBalancer"><g:message code="common.loadBalancer" /></a>
    </li>
    <li>
     <a href="#/admin/miscellaneous/portForwarding"><g:message code="common.portForwarding" /></a>
    </li>
    <li>
     <a href="#/admin/miscellaneous/vpn"><g:message code="common.vpnConnection" /></a>
    </li>
  </ul>
</div>
<div class="new-user"> 
    <form data-dojo-type="dijit.form.Form" id="adminMiscBandwidthForm" class="form-horizontal">
  <div class="row-fluid">
    <div class="value_dollar pull-right"><g:message code="default.valueIn" /><span id="miscBandwidthCurrencyValue"></span></div>  
  </div>
  <div class="row-fluid" id="adminMiscBandwidthPage">
      
  <!--<div class="row-fluid">-->
        <div class="span4 field-box control-group">
          <label for="" class="control-label">
            <g:message code="common.zone" />
            <span class="require">*</span>
          </label>
          <div class="controls">
          <div id="miscBandwidthZone"></div>
          </div>
        </div> 
        <div class="span6"  id="bandwidthZoneCostList">      
           <div id="miscBandwidthCostInfo"></div>                                
        </div>       
        <div class="span1 field-box control-group">            
          <button type="button" class="defaultbtn" id="miscBandwidthButton" data-dojo-type="dijit.form.Button" data-dojo-props="disabled: true" onclick="BandwidthInfo.updateShow()"><g:message code="default.button.update.common" /></button>
          <img src='images/preloader_circle.gif' alt='<g:message code="common.loading" />' height='16' width='23' id="miscBandwidthLoader" style="display: none"/>
        </div>
        <div class="field-box control-group" style="display: none">
          <label for="networkStratPort" id="adminIngressStartPort" class="control-label">
            <g:message code="common.pod" />
          </label>
          <div class="controls">
          <div id="miscBandwidthPod"></div>
          </div>
        </div>
        <div class="field-box control-group" style="display: none">
          <label for="networkEndPort" id="adminIngressEndPort" class="control-label">
            <g:message code="common.cluster" />
          </label>
          <div class="controls">
          <div id="miscBandwidthCluster"></div>
          </div>
        </div>            
      <!--</div>-->      
    
  </div>  
  </form>
  </div>
<div class="row-fluid">
  <div id="pad-wrapper">
    <div class="table-wrapper products-table">   
      <div class="row-fluid">      
        <div id="miscBandwidthInfo"></div>    
        <div class="alert alert-info hide" id="noMiscBandwidthMessageBox" style="display: none">
          <i class="icon-exclamation-sign"></i> 
          <g:message code="common.noBabdwidthInfo" />
        </div>
      </div>   
    </div>
  </div>    
</div>
<div data-dojo-type="dijit.Dialog" id="bandEditConformationDialog" title="<g:message code="default.button.update.common" />" class="span4">
    <p><g:message code="admin.updateItem" /></p> 
    <p class="alert alert-info"><g:message code="admin.updateItemInfoAllUser" /></p>
      <div class="row-fluid offset1">
        <button class="overflowLabel defaultbtn"  type="button"  data-dojo-type="dijit.form.Button" onclick="BandwidthInfo.update()"><g:message code="common.ok" /></button>
        <button class="overflowLabel cancelbtn"   type="button"  data-dojo-type="dijit.form.Button" onclick="BandwidthInfo.closeUpdate()"><g:message code="common.cancel" /></button>
    </div>
</div>
