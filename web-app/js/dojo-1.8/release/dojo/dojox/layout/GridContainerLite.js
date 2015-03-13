//>>built
require({cache:{"url:dojox/layout/resources/GridContainer.html":'<div id="${id}" class="gridContainer" dojoAttachPoint="containerNode" tabIndex="0" dojoAttachEvent="onkeypress:_selectFocus">\n\t<div dojoAttachPoint="gridContainerDiv">\n\t\t<table class="gridContainerTable" dojoAttachPoint="gridContainerTable" cellspacing="0" cellpadding="0">\n\t\t\t<tbody>\n\t\t\t\t<tr dojoAttachPoint="gridNode" >\n\t\t\t\t\t\n\t\t\t\t</tr>\n\t\t\t</tbody>\n\t\t</table>\n\t</div>\n</div>'}});
define("dojox/layout/GridContainerLite","dojo/_base/kernel,dojo/text!./resources/GridContainer.html,dojo/_base/declare,dojo/query,dojo/_base/sniff,dojo/dom-class,dojo/dom-style,dojo/dom-geometry,dojo/dom-construct,dojo/dom-attr,dojo/_base/array,dojo/_base/lang,dojo/_base/event,dojo/keys,dojo/topic,dijit/registry,dijit/focus,dijit/_base/focus,dijit/_WidgetBase,dijit/_TemplatedMixin,dijit/layout/_LayoutWidget,dojo/_base/NodeList,dojox/mdnd/AreaManager,dojox/mdnd/DropIndicator,dojox/mdnd/dropMode/OverDropMode,dojox/mdnd/AutoScroll".split(","),
function(q,x,y,v,k,z,t,j,u,r,m,p,s,i,w,n,o,A,B,C,D,E){q=y("dojox.layout.GridContainerLite",[D,C],{autoRefresh:!0,templateString:x,dragHandleClass:"dojoxDragHandle",nbZones:1,doLayout:!0,isAutoOrganized:!0,acceptTypes:[],colWidths:"",constructor:function(a){this.acceptTypes=(a||{}).acceptTypes||["text"];this._disabled=!0},postCreate:function(){this.inherited(arguments);this._grid=[];this._createCells();this.subscribe("/dojox/mdnd/drop","resizeChildAfterDrop");this.subscribe("/dojox/mdnd/drag/start",
"resizeChildAfterDragStart");this._dragManager=dojox.mdnd.areaManager();this._dragManager.autoRefresh=this.autoRefresh;this._dragManager.dragHandleClass=this.dragHandleClass;this.doLayout?this._border={h:k("ie")?j.getBorderExtents(this.gridContainerTable).h:0,w:6==k("ie")?1:0}:(t.set(this.domNode,"overflowY","hidden"),t.set(this.gridContainerTable,"height","auto"))},startup:function(){this._started||(this.isAutoOrganized?this._organizeChildren():this._organizeChildrenManually(),m.forEach(this.getChildren(),
function(a){a.startup()}),this._isShown()&&this.enableDnd(),this.inherited(arguments))},resizeChildAfterDrop:function(a,b){if(this._disabled)return!1;if(n.getEnclosingWidget(b.node)==this){var c=n.byNode(a);c.resize&&p.isFunction(c.resize)&&c.resize();c.set("column",a.parentNode.cellIndex);if(this.doLayout)c=this._contentBox.h,j.getContentBox(this.gridContainerDiv).h>=c&&t.set(this.gridContainerTable,"height",c-this._border.h+"px");return!0}return!1},resizeChildAfterDragStart:function(a,b){if(this._disabled)return!1;
return n.getEnclosingWidget(b.node)==this?(this._draggedNode=a,this.doLayout&&j.getMarginBox(this.gridContainerTable,{h:j.getContentBox(this.gridContainerDiv).h-this._border.h}),!0):!1},getChildren:function(){var a=new E;m.forEach(this._grid,function(b){v("> [widgetId]",b.node).map(n.byNode).forEach(function(b){a.push(b)})});return a},_isShown:function(){if("open"in this)return this.open;var a=this.domNode;return"none"!=a.style.display&&"hidden"!=a.style.visibility&&!z.contains(a,"dijitHidden")},
layout:function(){if(this.doLayout){var a=this._contentBox;j.getMarginBox(this.gridContainerTable,{h:a.h-this._border.h});j.getContentBox(this.domNode,{w:a.w-this._border.w})}m.forEach(this.getChildren(),function(a){a.resize&&p.isFunction(a.resize)&&a.resize()})},onShow:function(){this._disabled&&this.enableDnd()},onHide:function(){this._disabled||this.disableDnd()},_createCells:function(){if(0===this.nbZones)this.nbZones=1;for(var a=this.acceptTypes.join(","),b=0,c=this.colWidths||[],d=[],h,f=0,
b=0;b<this.nbZones;b++)d.length<c.length?(f+=c[b],d.push(c[b])):(h||(h=(100-f)/(this.nbZones-b)),d.push(h));for(b=0;b<this.nbZones;)this._grid.push({node:u.create("td",{"class":"gridContainerZone",accept:a,id:this.id+"_dz"+b,style:{width:d[b]+"%"}},this.gridNode)}),b++},_getZonesAttr:function(){return v(".gridContainerZone",this.containerNode)},enableDnd:function(){var a=this._dragManager;m.forEach(this._grid,function(b){a.registerByNode(b.node)});a._dropMode.updateAreas(a._areaList);this._disabled=
!1},disableDnd:function(){var a=this._dragManager;m.forEach(this._grid,function(b){a.unregister(b.node)});a._dropMode.updateAreas(a._areaList);this._disabled=!0},_organizeChildren:function(){for(var a=dojox.layout.GridContainerLite.superclass.getChildren.call(this),b=this.nbZones,c=Math.floor(a.length/b),d=a.length%b,h=0,f=0;f<b;f++){for(var e=0;e<c;e++)this._insertChild(a[h],f),h++;if(0<d){try{this._insertChild(a[h],f),h++}catch(g){console.error("Unable to insert child in GridContainer",g)}d--}else if(0===
c)break}},_organizeChildrenManually:function(){for(var a=dojox.layout.GridContainerLite.superclass.getChildren.call(this),b=a.length,c,d=0;d<b;d++){c=a[d];try{this._insertChild(c,c.column-1)}catch(h){console.error("Unable to insert child in GridContainer",h)}}},_insertChild:function(a,b,c){var d=this._grid[b].node,h=d.childNodes.length;if("undefined"===typeof c||c>h)c=h;this._disabled?(u.place(a.domNode,d,c),r.set(a.domNode,"tabIndex","0")):a.dragRestriction?(u.place(a.domNode,d,c),r.set(a.domNode,
"tabIndex","0")):this._dragManager.addDragItem(d,a.domNode,c,!0);a.set("column",b);return a},removeChild:function(a){this._disabled?this.inherited(arguments):this._dragManager.removeDragItem(a.domNode.parentNode,a.domNode)},addService:function(a,b,c){kernel.deprecated("addService is deprecated.","Please use  instead.","Future");this.addChild(a,b,c)},addChild:function(a,b,c){a.domNode.id=a.id;dojox.layout.GridContainerLite.superclass.addChild.call(this,a,0);if(0>b||void 0==b)b=0;0>=c&&(c=0);try{return this._insertChild(a,
b,c)}catch(d){console.error("Unable to insert child in GridContainer",d)}return null},_setColWidthsAttr:function(a){this.colWidths=p.isString(a)?a.split(","):p.isArray(a)?a:[a];this._started&&this._updateColumnsWidth()},_updateColumnsWidth:function(){var a=this._grid.length,b=this.colWidths||[],c=[],d,h=0,f;for(f=0;f<a;f++)c.length<b.length?(h+=1*b[f],c.push(b[f])):(d||(d=(100-h)/(this.nbZones-f),0>d&&(d=100/this.nbZones)),c.push(d),h+=1*d);if(100<h){b=100/h;for(f=0;f<c.length;f++)c[f]*=b}for(f=0;f<
a;f++)this._grid[f].node.style.width=c[f]+"%"},_selectFocus:function(a){if(!this._disabled){var b=a.keyCode,c=null,d=A.getFocus().node,h=this._dragManager,f,e,g;if(d==this.containerNode)switch(d=this.gridNode.childNodes,b){case i.DOWN_ARROW:case i.RIGHT_ARROW:f=!1;for(e=0;e<d.length;e++){b=d[e].childNodes;for(g=0;g<b.length;g++)if(c=b[g],null!=c&&"none"!=c.style.display){o.focus(c);s.stop(a);f=!0;break}if(f)break}break;case i.UP_ARROW:case i.LEFT_ARROW:d=this.gridNode.childNodes;f=!1;for(e=d.length-
1;0<=e;e--){b=d[e].childNodes;for(g=b.length;0<=g;g--)if(c=b[g],null!=c&&"none"!=c.style.display){o.focus(c);s.stop(a);f=!0;break}if(f)break}}else if(d.parentNode.parentNode==this.gridNode){var l=b==i.UP_ARROW||b==i.LEFT_ARROW?"lastChild":"firstChild";g=b==i.UP_ARROW||b==i.LEFT_ARROW?"previousSibling":"nextSibling";switch(b){case i.UP_ARROW:case i.DOWN_ARROW:s.stop(a);f=!1;for(var j=d;!f;){b=j.parentNode.childNodes;for(e=c=0;e<b.length&&!("none"!=b[e].style.display&&c++,1<c);e++);if(1==c)return;c=
null==j[g]?j.parentNode[l]:j[g];"none"===c.style.display?j=c:f=!0}if(a.shiftKey){a=d.parentNode;for(e=0;e<this.gridNode.childNodes.length&&!(a==this.gridNode.childNodes[e]);e++);b=this.gridNode.childNodes[e].childNodes;for(g=0;g<b.length&&!(c==b[g]);g++);(k("mozilla")||k("webkit"))&&e--;c=n.byNode(d);c.dragRestriction?w.publish("/dojox/layout/gridContainer/moveRestriction",this):(h.removeDragItem(a,d),this.addChild(c,e,g),r.set(d,"tabIndex","0"),o.focus(d))}else o.focus(c);break;case i.RIGHT_ARROW:case i.LEFT_ARROW:if(s.stop(a),
a.shiftKey){a=0;if(null==d.parentNode[g])k("ie")&&b==i.LEFT_ARROW&&(a=this.gridNode.childNodes.length-1);else if(3==d.parentNode[g].nodeType)a=this.gridNode.childNodes.length-2;else{for(e=0;e<this.gridNode.childNodes.length&&!(d.parentNode[g]==this.gridNode.childNodes[e]);e++)a++;(k("mozilla")||k("webkit"))&&a--}c=n.byNode(d);l=d.getAttribute("dndtype");l=null==l?c&&c.dndType?c.dndType.split(/\s*,\s*/):["text"]:l.split(/\s*,\s*/);f=!1;for(e=0;e<this.acceptTypes.length;e++)for(g=0;g<l.length;g++)if(l[g]==
this.acceptTypes[e]){f=!0;break}if(f&&!c.dragRestriction){e=d.parentNode;g=0;if(i.LEFT_ARROW==b){b=a;if(k("mozilla")||k("webkit"))b=a+1;g=this.gridNode.childNodes[b].childNodes.length}d=h.removeDragItem(e,d);this.addChild(c,a,g);r.set(d,"tabIndex","0");o.focus(d)}else w.publish("/dojox/layout/gridContainer/moveRestriction",this)}else{for(d=d.parentNode;null===c;)if(d=null!==d[g]&&3!==d[g].nodeType?d[g]:"previousSibling"===g?d.parentNode.childNodes[d.parentNode.childNodes.length-1]:d.parentNode.childNodes[k("ie")?
0:1],(c=d[l])&&"none"==c.style.display){b=c.parentNode.childNodes;h=null;if("previousSibling"==g)for(e=b.length-1;0<=e;e--){if("none"!=b[e].style.display){h=b[e];break}}else for(e=0;e<b.length;e++)if("none"!=b[e].style.display){h=b[e];break}h?c=h:(d=c,d=d.parentNode,c=null)}o.focus(c)}}}}},destroy:function(){var a=this._dragManager;m.forEach(this._grid,function(b){a.unregister(b.node)});this.inherited(arguments)}});q.ChildWidgetProperties={column:"1",dragRestriction:!1};p.extend(B,q.ChildWidgetProperties);
return q});