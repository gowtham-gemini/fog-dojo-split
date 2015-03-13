//>>built
define("dojox/dgauges/GaugeBase","dojo/_base/lang,dojo/_base/declare,dojo/dom-geometry,dijit/registry,dijit/_WidgetBase,dojo/_base/html,dojo/_base/event,dojox/gfx,dojox/widget/_Invalidating,./ScaleBase,dojox/gfx/matrix".split(","),function(e,h,f,i,j,k,m,l,d,g){return h("dojox.dgauges.GaugeBase",[j,d],{_elements:null,_scales:null,_elementsIndex:null,_elementsRenderers:null,_gfxGroup:null,_mouseShield:null,_widgetBox:null,_node:null,value:0,_mainIndicator:null,_getValueAttr:function(){if(this._mainIndicator)return this._mainIndicator.get("value");
this._setMainIndicator();return this._mainIndicator?this._mainIndicator.get("value"):this.value},_setValueAttr:function(a){this._set("value",a);this._mainIndicator?this._mainIndicator.set("value",a):(this._setMainIndicator(),this._mainIndicator&&this._mainIndicator.set("value",a))},_setMainIndicator:function(){for(var a,c=0;c<this._scales.length;c++)if(a=this._scales[c].getIndicator("indicator"))this._mainIndicator=a},_resetMainIndicator:function(){this._mainIndicator=null},font:null,constructor:function(a,
c){this.font={family:"Helvetica",style:"normal",variant:"small-caps",weight:"bold",size:"10pt",color:"black"};this._elements=[];this._scales=[];this._elementsIndex={};this._elementsRenderers={};this._node=i.byId(c);var b=k.getMarginBox(c);this.surface=l.createSurface(this._node,b.w||1,b.h||1);this._widgetBox=b;this._baseGroup=this.surface.createGroup();this._mouseShield=this._baseGroup.createGroup();this._gfxGroup=this._baseGroup.createGroup()},_setCursor:function(a){if(this._node)this._node.style.cursor=
a},_computeBoundingBox:function(a){return a?a.getBoundingBox():{x:0,y:0,width:0,height:0}},destroy:function(){this.surface.destroy();this.inherited(arguments)},resize:function(a,c){var b;switch(arguments.length){case 1:b=e.mixin({},a);f.setMarginBox(this._node,b);break;case 2:b={w:a,h:c},f.setMarginBox(this._node,b)}this._widgetBox=b=f.getMarginBox(this._node);var d=this.surface.getDimensions();return d.width!=b.w||d.height!=b.h?(this.surface.setDimensions(b.w,b.h),this._mouseShield.clear(),this._mouseShield.createRect({x:0,
y:0,width:b.w,height:b.h}).setFill([0,0,0,0]),this.invalidateRendering()):this},addElement:function(a,c){this._elementsIndex[a]&&this._elementsIndex[a]!=c&&this.removeElement(a);if(e.isFunction(c)){var b={};e.mixin(b,new d);b._name=a;b._gfxGroup=this._gfxGroup.createGroup();b.width=0;b.height=0;b._isGFX=!0;b.refreshRendering=function(){b._gfxGroup.clear();return c(b._gfxGroup,b.width,b.height)};this._elements.push(b);this._elementsIndex[a]=b}else c._name=a,c._gfxGroup=this._gfxGroup.createGroup(),
c._gauge=this,this._elements.push(c),this._elementsIndex[a]=c,c instanceof g&&this._scales.push(c);return this.invalidateRendering()},removeElement:function(a){var c=this._elementsIndex[a];c&&(c._gfxGroup.removeShape(),this._elements.splice(this._elements.indexOf(c),1),c instanceof g&&(this._scales.splice(this._scales.indexOf(c),1),this._resetMainIndicator()),delete this._elementsIndex[a],delete this._elementsRenderers[a]);this.invalidateRendering();return c},getElement:function(a){return this._elementsIndex[a]},
getElementRenderer:function(a){return this._elementsRenderers[a]},onStartEditing:function(){},onEndEditing:function(){}})});