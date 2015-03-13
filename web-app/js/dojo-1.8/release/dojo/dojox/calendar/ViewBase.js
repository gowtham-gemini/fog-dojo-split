//>>built
define("dojox/calendar/ViewBase","dojo/_base/declare,dojo/_base/lang,dojo/_base/array,dojo/_base/window,dojo/_base/event,dojo/_base/html,dojo/_base/sniff,dojo/query,dojo/dom,dojo/dom-style,dojo/dom-construct,dojo/dom-geometry,dojo/on,dojo/date,dojo/date/locale,dijit/_WidgetBase,dojox/widget/_Invalidating,dojox/widget/Selection,dojox/calendar/time,./StoreMixin".split(","),function(w,i,o,t,x,y,k,D,E,q,u,v,F,r,s,z,A,B,n,C){return w("dojox.calendar.ViewBase",[z,C,A,B],{datePackage:r,_calendar:"gregorian",
viewKind:null,_layoutStep:1,_layoutUnit:"day",resizeCursor:"n-resize",formatItemTimeFunc:null,_getFormatItemTimeFuncAttr:function(){return null!=this.owner?this.owner.get("formatItemTimeFunc"):this.formatItemTimeFunc},_viewHandles:null,doubleTapDelay:300,constructor:function(a){a=a||{};this._calendar=a.datePackage?a.datePackage.substr(a.datePackage.lastIndexOf(".")+1):this._calendar;this.dateModule=a.datePackage?i.getObject(a.datePackage,!1):r;this.dateClassObj=this.dateModule.Date||Date;this.dateLocaleModule=
a.datePackage?i.getObject(a.datePackage+".locale",!1):s;this.rendererPool=[];this.rendererList=[];this.itemToRenderer={};this._viewHandles=[]},destroy:function(a){for(;0<this.rendererList.length;)this._destroyRenderer(this.rendererList.pop());for(kind in this._rendererPool){var b=this._rendererPool[kind];if(b)for(;0<b.length;)this._destroyRenderer(b.pop())}for(;0<this._viewHandles.length;)this._viewHandles.pop().remove();this.inherited(arguments)},_createRenderData:function(){},_validateProperties:function(){},
_setText:function(a,b,c){if(null!=b)if(!c&&a.hasChildNodes())a.childNodes[0].childNodes[0].nodeValue=b;else{for(;a.hasChildNodes();)a.removeChild(a.lastChild);var e=t.doc.createElement("span");this.applyTextDir(e,b);c?e.innerHTML=b:e.appendChild(t.doc.createTextNode(b));a.appendChild(e)}},isAscendantHasClass:function(a,b,c){for(;a!=b&&a!=document;){if(dojo.hasClass(a,c))return!0;a=a.parentNode}return!1},isWeekEnd:function(a){return s.isWeekend(a)},getWeekNumberLabel:function(a){a.toGregorian&&(a=
a.toGregorian());return s.format(a,{selector:"date",datePattern:"w"})},floorToDay:function(a,b){return n.floorToDay(a,b,this.dateClassObj)},floorToMonth:function(a,b){return n.floorToMonth(a,b,this.dateClassObj)},floorDate:function(a,b,c,e){return n.floor(a,b,c,e,this.dateClassObj)},isToday:function(a){return n.isToday(a,this.dateClassObj)},isStartOfDay:function(a){return n.isStartOfDay(a,this.dateClassObj,this.dateModule)},isOverlapping:function(a,b,c,e,d,f){if(null==b||null==e||null==c||null==d)return!1;
a=a.dateModule;if(f){if(1==a.compare(b,d)||1==a.compare(e,c))return!1}else if(-1!=a.compare(b,d)||-1!=a.compare(e,c))return!1;return!0},computeRangeOverlap:function(a,b,c,e,d,f){var h=a.dateModule;if(null==b||null==e||null==c||null==d)return null;var i=h.compare(b,d),g=h.compare(e,c);if(f){if(0==i||1==i||0==g||1==g)return null}else if(1==i||1==g)return null;return[this.newDate(0<h.compare(b,e)?b:e,a),this.newDate(0<h.compare(c,d)?d:c,a)]},isSameDay:function(a,b){return null==a||null==b?!1:a.getFullYear()==
b.getFullYear()&&a.getMonth()==b.getMonth()&&a.getDate()==b.getDate()},computeProjectionOnDate:function(a,b,c,e){var d=a.dateModule;if(0>=e||-1==d.compare(c,b))return 0;var f=this.floorToDay(b,!1,a);if(c.getDate()!=f.getDate())if(c.getMonth()==f.getMonth()){if(c.getDate()<f.getDate())return 0;if(c.getDate()>f.getDate())return e}else if(c.getFullYear()==f.getFullYear()){if(c.getMonth()<f.getMonth())return 0;if(c.getMonth()>f.getMonth())return e}else{if(c.getFullYear()<f.getFullYear())return 0;if(c.getFullYear()>
f.getFullYear())return e}if(this.isSameDay(b,c)){f=i.clone(b);d=0;null!=a.minHours&&0!=a.minHours&&(f.setHours(a.minHours),d=3600*f.getHours()+60*f.getMinutes()+f.getSeconds());f=i.clone(b);null==a.maxHours||24==a.maxHours?a=86400:(f.setHours(a.maxHours),a=3600*f.getHours()+60*f.getMinutes()+f.getSeconds());b=3600*c.getHours()+60*c.getMinutes()+c.getSeconds()-d;if(0>b)return 0;if(b>a)return e;e=e*b/(a-d)}else{if(c.getDate()<b.getDate()&&c.getMonth()==b.getMonth())return 0;c=this.floorToDay(c);f=a.dateModule.add(b,
"day",1);f=this.floorToDay(f,!1,a);e=1==d.compare(c,b)&&0==d.compare(c,f)||1==d.compare(c,f)?e:0}return e},getTime:function(){return null},newDate:function(a){return n.newDate(a,this.dateClassObj)},_isItemInView:function(a){var b=this.renderData,c=b.dateModule;return-1==c.compare(a.startTime,b.startTime)||1==c.compare(a.endTime,b.endTime)?!1:!0},_ensureItemInView:function(a){var b=this.renderData,c=b.dateModule,e=Math.abs(c.difference(a.startTime,a.endTime,"millisecond")),d=!1;if(-1==c.compare(a.startTime,
b.startTime))a.startTime=b.startTime,a.endTime=c.add(a.startTime,"millisecond",e),d=!0;else if(1==c.compare(a.endTime,b.endTime))a.endTime=b.endTime,a.startTime=c.add(a.endTime,"millisecond",-e),d=!0;return d},scrollable:!0,autoScroll:!0,_autoScroll:function(){return!1},scrollMethod:"auto",_setScrollMethodAttr:function(a){if(this.scrollMethod!=a){this.scrollMethod=a;if(void 0!==this._domScroll)this._domScroll?q.set(this.sheetContainer,this._cssPrefix+"transform","translateY(0px)"):this.scrollContainer.scrollTop=
0;delete this._domScroll;a=this._getScrollPosition();delete this._scrollPos;this._setScrollPosition(a)}},_startAutoScroll:function(a){var b=this._scrollProps;if(!b)b=this._scrollProps={};b.scrollStep=a;if(!b.isScrolling)b.isScrolling=!0,b.scrollTimer=setInterval(i.hitch(this,this._onScrollTimer_tick),10)},_stopAutoScroll:function(){var a=this._scrollProps;if(a&&a.isScrolling)clearInterval(a.scrollTimer),a.scrollTimer=null;this._scrollProps=null},_onScrollTimer_tick:function(){},_scrollPos:0,getCSSPrefix:function(){if(k("ie"))return"-ms-";
if(k("webkit"))return"-webkit-";if(k("mozilla"))return"-moz-";if(k("opera"))return"-o-"},_setScrollPosition:function(a){if(this._scrollPos!=a){if(void 0===this._domScroll){var b=this.get("scrollMethod");this._domScroll="auto"===b?!k("ios")&&!k("android")&&!k("webkit"):"dom"===b}b=v.getMarginBox(this.scrollContainer);b=v.getMarginBox(this.sheetContainer).h-b.h;0>a?a=0:a>b&&(a=b);this._scrollPos=a;if(this._domScroll)this.scrollContainer.scrollTop=a;else{if(!this._cssPrefix)this._cssPrefix=this.getCSSPrefix();
q.set(this.sheetContainer,this._cssPrefix+"transform","translateY(-"+a+"px)")}}},_getScrollPosition:function(){return this._scrollPos},scrollView:function(){},ensureVisibility:function(){},_getStoreAttr:function(){return this.owner?this.owner.get("store"):this.store},_setItemsAttr:function(a){this._set("items",a);this.displayedItemsInvalidated=!0},_refreshItemsRendering:function(){var a=this.renderData;this._computeVisibleItems(a);this._layoutRenderers(a)},invalidateLayout:function(){this._layoutRenderers(this.renderData)},
resize:function(){},computeOverlapping:function(a,b){if(0==a.length)return{numLanes:0,addedPassRes:[1]};for(var c=[],e=0;e<a.length;e++)this._layoutPass1(a[e],c);e=null;b&&(e=i.hitch(this,b)(c));return{numLanes:c.length,addedPassRes:e}},_layoutPass1:function(a,b){for(var c=!0,e=0;e<b.length;e++){for(var d=b[e],c=!1,f=0;f<d.length&&!c;f++)if(d[f].start<a.end&&a.start<d[f].end)c=!0,d[f].extent=1;if(!c){a.lane=e;a.extent=-1;d.push(a);return}}b.push([a]);a.lane=b.length-1;a.extent=-1},_layoutInterval:function(){},
layoutPriorityFunction:null,_sortItemsFunction:function(a,b){var c=this.dateModule.compare(a.startTime,b.startTime);0==c&&(c=-1*this.dateModule.compare(a.endTime,b.endTime));return c},_layoutRenderers:function(a){if(a.items){this._recycleItemRenderers();for(var b=a.dateModule,c=this.newDate(a.startTime),e=i.clone(c),d=a.items.concat(),f=[],h,j=0;-1==b.compare(c,a.endTime)&&0<d.length;){var c=b.add(c,this._layoutUnit,this._layoutStep),c=this.floorToDay(c,!0,a),g=i.clone(c);a.minHours&&e.setHours(a.minHours);
a.maxHours&&24!=a.maxHours&&(g=b.add(c,"day",-1),g=this.floorToDay(g,!0,a),g.setHours(a.maxHours));h=o.filter(d,function(c){var d=this.isOverlapping(a,c.startTime,c.endTime,e,g);d?1==b.compare(c.endTime,g)&&f.push(c):f.push(c);return d},this);d=f;f=[];0<h.length&&(h.sort(i.hitch(this,this.layoutPriorityFunction?this.layoutPriorityFunction:this._sortItemsFunction)),this._layoutInterval(a,j,e,g,h));e=i.clone(c);j++}this._onRenderersLayoutDone(this)}},_recycleItemRenderers:function(a){for(;0<this.rendererList.length;)this._recycleRenderer(this.rendererList.pop(),
a);this.itemToRenderer={}},rendererPool:null,rendererList:null,itemToRenderer:null,getRenderers:function(a){if(null==a||null==a.id)return null;a=this.itemToRenderer[a.id];return null==a?null:a.concat()},_rendererHandles:{},itemToRendererKindFunc:null,_itemToRendererKind:function(a){return this.itemToRendererKindFunc?this.itemToRendererKindFunc(a):this._defaultItemToRendererKindFunc(a)},_defaultItemToRendererKindFunc:function(){return null},_createRenderer:function(a,b,c,e){if(null!=a&&null!=b&&null!=
c){var d,f=this.rendererPool[b];null!=f&&(d=f.shift());null==d?(c=new c,d=u.create("div"),d.className="dojoxCalendarEventContainer "+e,d.appendChild(c.domNode),d={renderer:c,container:c.domNode,kind:b},this._onRendererCreated(d)):(c=d.renderer,this._onRendererReused(c));c.owner=this;c.set("rendererKind",b);c.set("item",a);b=this.itemToRenderer[a.id];null==b&&(this.itemToRenderer[a.id]=b=[]);b.push(d);this.rendererList.push(d);return d}return null},_onRendererCreated:function(a){this.onRendererCreated(a);
var b=this.owner&&this.owner.owner?this.owner.owner:this.owner;if(b)b.onRendererCreated(a)},onRendererCreated:function(){},_onRendererRecycled:function(a){this.onRendererRecycled(a);var b=this.owner&&this.owner.owner?this.owner.owner:this.owner;if(b)b.onRendererRecycled(a)},onRendererRecycled:function(){},_onRendererReused:function(a){this.onRendererReused(a);var b=this.owner&&this.owner.owner?this.owner.owner:this.owner;if(b)b.onRendererReused(a)},onRendererReused:function(){},_onRendererDestroyed:function(a){this.onRendererDestroyed(a);
var b=this.owner&&this.owner.owner?this.owner.owner:this.owner;if(b)b.onRendererDestroyed(a)},onRendererDestroyed:function(){},_onRenderersLayoutDone:function(a){this.onRenderersLayoutDone(a);if(null!=this.owner)this.owner.onRenderersLayoutDone(a)},onRenderersLayoutDone:function(){},_recycleRenderer:function(a,b){this._onRendererRecycled(a);var c=this.rendererPool[a.kind];null==c?this.rendererPool[a.kind]=[a]:c.push(a);b&&a.container.parentNode.removeChild(a.container);q.set(a.container,"display",
"none");a.renderer.owner=null;a.renderer.set("item",null)},_destroyRenderer:function(a){this._onRendererDestroyed(a);var b=a.renderer;o.forEach(b.__handles,function(a){a.remove()});b.destroy&&b.destroy();y.destroy(a.container)},_destroyRenderersByKind:function(a){for(var b=[],c=0;c<this.rendererList.length;c++){var e=this.rendererList[c];e.kind==a?this._destroyRenderer(e):b.push(e)}this.rendererList=b;if(a=this.rendererPool[a])for(;0<a.length;)this._destroyRenderer(a.pop())},_updateEditingCapabilities:function(a,
b){var c=this.isItemMoveEnabled(a,b.rendererKind),e=this.isItemResizeEnabled(a,b.rendererKind),d=!1;c!=b.get("moveEnabled")&&(b.set("moveEnabled",c),d=!0);e!=b.get("resizeEnabled")&&(b.set("resizeEnabled",e),d=!0);d&&b.updateRendering()},updateRenderers:function(a,b){if(null!=a)for(var c=i.isArray(a)?a:[a],e=0;e<c.length;e++){var d=c[e];if(!(null==d||null==d.id)){var f=this.itemToRenderer[d.id];if(null!=f)for(var h=this.isItemSelected(d),j=this.isItemHovered(d),g=this.isItemBeingEdited(d),l=this.showFocus?
this.isItemFocused(d):!1,k=0;k<f.length;k++){var m=f[k].renderer;m.set("hovered",j);m.set("selected",h);m.set("edited",g);m.set("focused",l);this.applyRendererZIndex(d,f[k],j,h,g,l);b||(m.set("item",d),m.updateRendering&&m.updateRendering())}}}},applyRendererZIndex:function(a,b,c,e,d){q.set(b.container,{zIndex:d||e?20:void 0==a.lane?0:a.lane})},getIdentity:function(a){return this.owner?this.owner.getIdentity(a):a.id},_setHoveredItem:function(a,b){if(this.owner)this.owner._setHoveredItem(a,b);else if(this.hoveredItem&&
a&&this.hoveredItem.id!=a.id||null==a||null==this.hoveredItem){var c=this.hoveredItem;this.hoveredItem=a;this.updateRenderers([c,this.hoveredItem],!0);a&&b&&this._updateEditingCapabilities(a,b)}},hoveredItem:null,isItemHovered:function(a){return this._isEditing&&this._edProps?a.id==this._edProps.editedItem.id:this.owner?this.owner.isItemHovered(a):null!=this.hoveredItem&&this.hoveredItem.id==a.id},isItemFocused:function(a){return this._isItemFocused?this._isItemFocused(a):!1},_setSelectionModeAttr:function(a){this.owner?
this.owner.set("selectionMode",a):this.inherited(arguments)},_getSelectionModeAttr:function(a){return this.owner?this.owner.get("selectionMode"):this.inherited(arguments)},_setSelectedItemAttr:function(a){this.owner?this.owner.set("selectedItem",a):this.inherited(arguments)},_getSelectedItemAttr:function(){return this.owner?this.owner.get("selectedItem"):this.selectedItem},_setSelectedItemsAttr:function(a){this.owner?this.owner.set("selectedItems",a):this.inherited(arguments)},_getSelectedItemsAttr:function(){return this.owner?
this.owner.get("selectedItems"):this.inherited(arguments)},isItemSelected:function(a){return this.owner?this.owner.isItemSelected(a):this.inherited(arguments)},selectFromEvent:function(a,b,c,e){this.owner?this.owner.selectFromEvent(a,b,c,e):this.inherited(arguments)},setItemSelected:function(a,b){this.owner?this.owner.setItemSelected(a,b):this.inherited(arguments)},createItemFunc:null,_getCreateItemFuncAttr:function(){return this.owner?this.owner.get("createItemFunc"):this.createItemFunc},createOnGridClick:!1,
_getCreateOnGridClickAttr:function(){return this.owner?this.owner.get("createOnGridClick"):this.createOnGridClick},_gridMouseDown:!1,_onGridMouseDown:function(a){this._gridMouseDown=!0;this.showFocus=!1;this._isEditing&&this._endItemEditing("mouse",!1);this._doEndItemEditing(this.owner,"mouse");this.set("focusedItem",null);this.selectFromEvent(a,null,null,!0);this._setTabIndexAttr&&this[this._setTabIndexAttr].focus();if(this._onRendererHandleMouseDown){var b=this.get("createItemFunc");if(b){var b=
b(this,this.getTime(a),a),c=this.get("store");if(b&&null!=c&&(c.put(b),(b=this.getRenderers(b))&&0<b.length))(b=b[0])&&this._onRendererHandleMouseDown(a,b.renderer,"resizeEnd")}}},_onGridMouseMove:function(){},_onGridMouseUp:function(){},_onGridTouchStart:function(a){var b=this._edProps;this._gridProps={event:a,fromItem:this.isAscendantHasClass(a.target,this.eventContainer,"dojoxCalendarEventContainer")};if(this._isEditing){if(this._gridProps)this._gridProps.editingOnStart=!0;i.mixin(b,this._getTouchesOnRenderers(a,
b.editedItem));if(0==b.touchesLen){if(b&&b.endEditingTimer)clearTimeout(b.endEditingTimer),b.endEditingTimer=null;this._endItemEditing("touch",!1)}}this._doEndItemEditing(this.owner,"touch");x.stop(a)},_doEndItemEditing:function(a,b){if(a&&a._isEditing){if((p=a._edProps)&&p.endEditingTimer)clearTimeout(p.endEditingTimer),p.endEditingTimer=null;a._endItemEditing(b,!1)}},_onGridTouchEnd:function(){},_onGridTouchMove:function(){},__fixEvt:function(a){return a},_dispatchCalendarEvt:function(a,b){a=this.__fixEvt(a);
this[b](a);if(this.owner)this.owner[b](a);return a},_onGridClick:function(a){a.triggerEvent||(a={date:this.getTime(a),triggerEvent:a});this._dispatchCalendarEvt(a,"onGridClick")},onGridClick:function(){},_onGridDoubleClick:function(a){a.triggerEvent||(a={date:this.getTime(a),triggerEvent:a});this._dispatchCalendarEvt(a,"onGridDoubleClick")},onGridDoubleClick:function(){},_onItemClick:function(a){this._dispatchCalendarEvt(a,"onItemClick")},onItemClick:function(){},_onItemDoubleClick:function(a){this._dispatchCalendarEvt(a,
"onItemDoubleClick")},onItemDoubleClick:function(){},_onItemContextMenu:function(a){this._dispatchCalendarEvt(a,"onItemContextMenu")},onItemContextMenu:function(){},_getStartEndRenderers:function(a){a=this.itemToRenderer[a.id];if(null!=a){if(1==a.length)return a=a[0].renderer,[a,a];for(var b=this.renderData,c=!1,e=!1,d=[],f=0;f<a.length;f++){var h=a[f].renderer;c||(c=0==b.dateModule.compare(h.item.range[0],h.item.startTime),d[0]=h);e||(e=0==b.dateModule.compare(h.item.range[1],h.item.endTime),d[1]=
h);if(c&&e)break}return d}},editable:!0,moveEnabled:!0,resizeEnabled:!0,isItemEditable:function(){return this.editable&&(this.owner?this.owner.isItemEditable():!0)},isItemMoveEnabled:function(a,b){return this.isItemEditable(a,b)&&this.moveEnabled&&(this.owner?this.owner.isItemMoveEnabled(a,b):!0)},isItemResizeEnabled:function(a,b){return this.isItemEditable(a,b)&&this.resizeEnabled&&(this.owner?this.owner.isItemResizeEnabled(a,b):!0)},_isEditing:!1,isItemBeingEdited:function(a){return this._isEditing&&
this._edProps&&this._edProps.editedItem&&this._edProps.editedItem.id==a.id},_setEditingProperties:function(a){this._edProps=a},_startItemEditing:function(a,b){this._isEditing=!0;var c=this._edProps;c.editedItem=a;c.eventSource=b;c.secItem=this._secondarySheet?this._findRenderItem(a.id,this._secondarySheet.renderData.items):null;c.ownerItem=this.owner?this._findRenderItem(a.id,this.items):null;if(!c.liveLayout){c.editSaveStartTime=a.startTime;c.editSaveEndTime=a.endTime;c.editItemToRenderer=this.itemToRenderer;
c.editItems=this.renderData.items;c.editRendererList=this.rendererList;this.renderData.items=[c.editedItem];var e=c.editedItem.id;this.itemToRenderer={};this.rendererList=[];var d=c.editItemToRenderer[e];c.editRendererIndices=[];o.forEach(d,i.hitch(this,function(a){null==this.itemToRenderer[e]?this.itemToRenderer[e]=[a]:this.itemToRenderer[e].push(a);this.rendererList.push(a)}));c.editRendererList=o.filter(c.editRendererList,function(a){return null!=a&&a.renderer.item.id!=e});delete c.editItemToRenderer[e]}this._layoutRenderers(this.renderData);
this._onItemEditBegin({item:a,eventSource:b})},_onItemEditBegin:function(a){this._editStartTimeSave=this.newDate(a.item.startTime);this._editEndTimeSave=this.newDate(a.item.endTime);this._dispatchCalendarEvt(a,"onItemEditBegin")},onItemEditBegin:function(){},_endItemEditing:function(a,b){this._isEditing=!1;var c=this._edProps;o.forEach(c.handles,function(a){a.remove()});if(!c.liveLayout)this.renderData.items=c.editItems,this.rendererList=c.editRendererList.concat(this.rendererList),i.mixin(this.itemToRenderer,
c.editItemToRenderer);var e=this.get("store");this._onItemEditEnd(i.mixin(this._createItemEditEvent(),{item:this.renderItemToItem(c.editedItem,e),renderItem:c.editedItem,eventSource:a,completed:!b}));this._layoutRenderers(this.renderData);this._edProps=null},_onItemEditEnd:function(a){this._dispatchCalendarEvt(a,"onItemEditEnd");if(!a.isDefaultPrevented())a.completed?this.get("store").put(a.item):(a.renderItem.startTime=this._editStartTimeSave,a.renderItem.endTime=this._editEndTimeSave)},onItemEditEnd:function(){},
_createItemEditEvent:function(){return{cancelable:!0,bubbles:!1,__defaultPrevent:!1,preventDefault:function(){this.__defaultPrevented=!0},isDefaultPrevented:function(){return this.__defaultPrevented}}},_startItemEditingGesture:function(a,b,c,e){var d=this._edProps;if(d&&null!=d.editedItem){this._editingGesture=!0;var f=d.editedItem;d.editKind=b;this._onItemEditBeginGesture(this.__fixEvt(i.mixin(this._createItemEditEvent(),{item:f,startTime:f.startTime,endTime:f.endTime,editKind:b,rendererKind:d.rendererKind,
triggerEvent:e,dates:a,eventSource:c})));d.itemBeginDispatched=!0}},_onItemEditBeginGesture:function(a){var b=this._edProps,c=b.editedItem,e=a.dates;b.editingTimeFrom=[];b.editingTimeFrom[0]=e[0];b.editingItemRefTime=[];b.editingItemRefTime[0]=this.newDate("resizeEnd"==b.editKind?c.endTime:c.startTime);"resizeBoth"==b.editKind&&(b.editingTimeFrom[1]=e[1],b.editingItemRefTime[1]=this.newDate(c.endTime));e=this.renderData.dateModule;b.inViewOnce=this._isItemInView(c);if("label"==b.rendererKind||this.roundToDay)b._itemEditBeginSave=
this.newDate(c.startTime),b._itemEditEndSave=this.newDate(c.endTime);b._initDuration=e.difference(c.startTime,c.endTime,c.allDay?"day":"millisecond");this._dispatchCalendarEvt(a,"onItemEditBeginGesture");if(!a.isDefaultPrevented()&&"mouse"==a.eventSource)b.editLayer=u.create("div",{style:"position: absolute; left:0; right:0; bottom:0; top:0; z-index:30; tabIndex:-1; background-image:url('"+this._blankGif+"'); cursor: "+("move"==a.editKind?"move":this.resizeCursor),onresizestart:function(){return!1},
onselectstart:function(){return!1}},this.domNode),b.editLayer.focus()},onItemEditBeginGesture:function(){},_waDojoxAddIssue:function(a,b,c){var e=this.renderData.dateModule;return"gregorian"!=this._calendar&&0>c?(a=a.toGregorian(),a=r.add(a,b,c),new this.renderData.dateClassObj(a)):e.add(a,b,c)},_computeItemEditingTimes:function(a,b,c,e){var a=this.renderData.dateModule,c=this._edProps,d=a.difference(c.editingTimeFrom[0],e[0],"millisecond");e[0]=this._waDojoxAddIssue(c.editingItemRefTime[0],"millisecond",
d);"resizeBoth"==b&&(d=a.difference(c.editingTimeFrom[1],e[1],"millisecond"),e[1]=this._waDojoxAddIssue(c.editingItemRefTime[1],"millisecond",d));return e},_moveOrResizeItemGesture:function(a,b,c){if(this._isEditing&&null!=a[0]){var e=this._edProps,d=e.editedItem,f=this.renderData.dateModule,h=e.editKind,j=[a[0]];"resizeBoth"==h&&(j[1]=a[1]);var j=this._computeItemEditingTimes(d,e.editKind,e.rendererKind,j,b),g=j[0],l=!1,a=i.clone(d.startTime),k=i.clone(d.endTime),m="keyboard"==e.eventSource?!1:this.allowStartEndSwap;
if("move"==h){if(0!=f.compare(d.startTime,g))l=f.difference(d.startTime,d.endTime,"millisecond"),d.startTime=this.newDate(g),d.endTime=f.add(d.startTime,"millisecond",l),l=!0}else if("resizeStart"==h){if(0!=f.compare(d.startTime,g)){if(-1!=f.compare(d.endTime,g))d.startTime=this.newDate(g);else if(m){if(d.startTime=this.newDate(d.endTime),d.endTime=this.newDate(g),e.editKind=h="resizeEnd","touch"==b)e.resizeEndTouchIndex=e.resizeStartTouchIndex,e.resizeStartTouchIndex=-1}else d.startTime=this.newDate(d.endTime),
d.startTime.setHours(g.getHours()),d.startTime.setMinutes(g.getMinutes()),d.startTime.setSeconds(g.getSeconds());l=!0}}else if("resizeEnd"==h){if(0!=f.compare(d.endTime,g)){if(1!=f.compare(d.startTime,g))d.endTime=this.newDate(g);else if(m){if(d.endTime=this.newDate(d.startTime),d.startTime=this.newDate(g),e.editKind=h="resizeStart","touch"==b)e.resizeStartTouchIndex=e.resizeEndTouchIndex,e.resizeEndTouchIndex=-1}else d.endTime=this.newDate(d.startTime),d.endTime.setHours(g.getHours()),d.endTime.setMinutes(g.getMinutes()),
d.endTime.setSeconds(g.getSeconds());l=!0}}else if("resizeBoth"==h){if(l=!0,g=this.newDate(g),j=this.newDate(j[1]),-1!=f.compare(g,j)&&(m?(m=g,g=j,j=m):l=!1),l)d.startTime=g,d.endTime=j}else return!1;if(!l)return!1;b=i.mixin(this._createItemEditEvent(),{item:d,startTime:d.startTime,endTime:d.endTime,editKind:h,rendererKind:e.rendererKind,triggerEvent:c,eventSource:b});"move"==h?this._onItemEditMoveGesture(b):this._onItemEditResizeGesture(b);if(1==f.compare(d.startTime,d.endTime))h=d.startTime,d.startTime=
d.startTime,d.endTime=h;l=0!=f.compare(a,d.startTime)||0!=f.compare(k,d.endTime);if(!l)return!1;this._layoutRenderers(this.renderData);if(e.liveLayout&&null!=e.secItem)e.secItem.startTime=d.startTime,e.secItem.endTime=d.endTime,this._secondarySheet._layoutRenderers(this._secondarySheet.renderData);else if(null!=e.ownerItem&&this.owner.liveLayout)e.ownerItem.startTime=d.startTime,e.ownerItem.endTime=d.endTime,this.owner._layoutRenderers(this.owner.renderData);return!0}},_findRenderItem:function(a,
b){for(var b=b||this.renderData.items,c=0;c<b.length;c++)if(b[c].id==a)return b[c];return null},_onItemEditMoveGesture:function(a){this._dispatchCalendarEvt(a,"onItemEditMoveGesture");if(!a.isDefaultPrevented()){var b=a.source._edProps,c=this.renderData,e=c.dateModule;"label"==b.rendererKind||this.roundToDay&&!a.item.allDay?(c=this.floorToDay(a.item.startTime,!1,c),c.setHours(b._itemEditBeginSave.getHours()),c.setMinutes(b._itemEditBeginSave.getMinutes()),e=e.add(c,"millisecond",b._initDuration)):
a.item.allDay?(c=this.floorToDay(a.item.startTime,!0),e=e.add(c,"day",b._initDuration)):(c=this.floorDate(a.item.startTime,this.snapUnit,this.snapSteps),e=e.add(c,"millisecond",b._initDuration));a.item.startTime=c;a.item.endTime=e;if(!b.inViewOnce)b.inViewOnce=this._isItemInView(a.item);b.inViewOnce&&this.stayInView&&this._ensureItemInView(a.item)}},_DAY_IN_MILLISECONDS:864E5,onItemEditMoveGesture:function(){},_onItemEditResizeGesture:function(a){this._dispatchCalendarEvt(a,"onItemEditResizeGesture");
if(!a.isDefaultPrevented()){var b=a.source._edProps,c=this.renderData,e=c.dateModule,d=a.item.startTime,f=a.item.endTime;"resizeStart"==a.editKind?a.item.allDay?d=this.floorToDay(a.item.startTime,!1,this.renderData):this.roundToDay?(d=this.floorToDay(a.item.startTime,!1,c),d.setHours(b._itemEditBeginSave.getHours()),d.setMinutes(b._itemEditBeginSave.getMinutes())):d=this.floorDate(a.item.startTime,this.snapUnit,this.snapSteps):"resizeEnd"==a.editKind?a.item.allDay?this.isStartOfDay(a.item.endTime)||
(f=this.floorToDay(a.item.endTime,!1,this.renderData),f=e.add(f,"day",1)):this.roundToDay?(f=this.floorToDay(a.item.endTime,!1,c),f.setHours(b._itemEditEndSave.getHours()),f.setMinutes(b._itemEditEndSave.getMinutes())):(f=this.floorDate(a.item.endTime,this.snapUnit,this.snapSteps),"mouse"==a.eventSource&&(f=e.add(f,this.snapUnit,this.snapSteps))):(d=this.floorDate(a.item.startTime,this.snapUnit,this.snapSteps),f=this.floorDate(a.item.endTime,this.snapUnit,this.snapSteps),f=e.add(f,this.snapUnit,this.snapSteps));
a.item.startTime=d;a.item.endTime=f;c=a.item.allDay||b._initDuration>=this._DAY_IN_MILLISECONDS&&!this.allowResizeLessThan24H;this.ensureMinimalDuration(this.renderData,a.item,c?"day":this.minDurationUnit,c?1:this.minDurationSteps,a.editKind);if(!b.inViewOnce)b.inViewOnce=this._isItemInView(a.item);b.inViewOnce&&this.stayInView&&this._ensureItemInView(a.item)}},onItemEditResizeGesture:function(){},_endItemEditingGesture:function(a,b){if(this._isEditing){this._editingGesture=!1;var c=this._edProps,
e=c.editedItem;c.itemBeginDispatched=!1;this._onItemEditEndGesture(i.mixin(this._createItemEditEvent(),{item:e,startTime:e.startTime,endTime:e.endTime,editKind:c.editKind,rendererKind:c.rendererKind,triggerEvent:b,eventSource:a}))}},_onItemEditEndGesture:function(a){var b=this._edProps;delete b._itemEditBeginSave;delete b._itemEditEndSave;this._dispatchCalendarEvt(a,"onItemEditEndGesture");if(!a.isDefaultPrevented()&&b.editLayer){if(k("ie"))b.editLayer.style.cursor="default";setTimeout(i.hitch(this,
function(){if(this.domNode)this.domNode.focus(),b.editLayer.parentNode.removeChild(b.editLayer),b.editLayer=null}),10)}},onItemEditEndGesture:function(){},ensureMinimalDuration:function(a,b,c,e,d){a=a.dateModule;if("resizeStart"==d){if(c=a.add(b.endTime,c,-e),1==a.compare(b.startTime,c))b.startTime=c}else if(c=a.add(b.startTime,c,e),-1==a.compare(b.endTime,c))b.endTime=c},doubleTapDelay:300,snapUnit:"minute",snapSteps:15,minDurationUnit:"hour",minDurationSteps:1,liveLayout:!1,stayInView:!0,allowStartEndSwap:!0,
allowResizeLessThan24H:!1})});