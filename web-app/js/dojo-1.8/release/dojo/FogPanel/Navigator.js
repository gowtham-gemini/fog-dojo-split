//>>built
define("FogPanel/Navigator","require,dojo/_base/declare,dojo/has,dojo/keys,dojo/ready,dijit/_Widget,dojo/dom-class,dijit/_KeyNavContainer,dijit/_TemplatedMixin,dojo/NodeList-traverse".split(","),function(i,e,j,k,l,f,d,g,h){return e("FogPanel.Navigator",[f,h,g],{templateString:'<div class="navbar-inner" tabIndex="${tabIndex}" data-dojo-attach-point="containerNode"><button type="button" class="btn btn-navbar visible-phone" data-dojo-attach-point="menuContainer"><span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span></button></div>',
baseClass:"navbar-inner",verticalManuBarId:"",postCreate:function(){var b=this;this.inherited(arguments);this.menuContainer.onclick=function(){b.onToggleButtonClick()}},setLogo:function(){},disableNavigator:function(){var b=dojo.query(".navbar-inner .dijitToolbar .dashboardContent");dojo.forEach(b,function(a){d.add(a,"disable")})},enableNavigator:function(){dojo.query(".navbar-inner .dijitToolbar .dashboardContent").forEach(function(b){d.remove(b,"disable")})},onToggleButtonClick:function(){var b=
this,a=dojo.byId(b.id),a=dojo.query(a).parent()[0],a=dojo.query(a).next()[0];a.onclick=function(){b.onToggleButtonClick()};var a=dojo.byId(a.id),c="",c=a.className.split(" ")[1];"display"==c?d.remove(a,"display"):(""==c||void 0==c||"display"!=c)&&d.add(a,"display")}})});