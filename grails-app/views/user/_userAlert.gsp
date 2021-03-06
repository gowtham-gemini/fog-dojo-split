<%@ page contentType="text/html;charset=UTF-8" %>
<div class="row-fluid">
<div class="span12 breadcrumbs">
  <ul>
    <li><a href="#/user/home"><i class="icon-home"></i></a></li> 
    <li>/</li>
    <li><a href="#/user/home/accountAlert"><g:message code="menu.user.activity"/></a></li>    
    <li>/</li>
    <li><g:message code="menu.user.activity.userAlert"/></li>
  </ul>
</div>
</div>
<div class="row-fluid">   
<ul class="nav nav-tabs span12 customNav">
  <li class="active">
    <a href="#/user/home/userAlert"><g:message code="menu.user.activity.userAlert"/></a>
  </li>
  <li>
      <a href="#/user/home/billingAlert"><g:message code="menu.user.activity.billingAlert"/></a>
    </li>   
</ul>
</div>
<div class="row-fluid">
  <div id="pad-wrapper" class="new-user">
    <div class="table-wrapper products-table"> 
    <div class="row-fluid">
      <div id="userAlertInfoGrid">
      </div>
      <div class="alert alert-info hide" id="noUserAlertsMessageBox" style="display: none">
        <i class="icon-exclamation-sign"></i> 
        <g:message code="menu.user.activity.noAlert"/>
      </div>
    </div>
    </div>
  </div>
</div>
