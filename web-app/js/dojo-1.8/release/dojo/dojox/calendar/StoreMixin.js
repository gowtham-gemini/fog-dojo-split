//>>built
define("dojox/calendar/StoreMixin","dojo/_base/declare,dojo/_base/array,dojo/_base/html,dojo/_base/lang,dojo/dom-class,dojo/Stateful,dojo/when".split(","),function(g,h,k,d,l,i,j){return g("dojox.calendar.StoreMixin",i,{store:null,query:{},startTimeAttr:"startTime",endTimeAttr:"endTime",summaryAttr:"summary",allDayAttr:"allDay",cssClassFunc:null,decodeDate:null,encodeDate:null,displayedItemsInvalidated:!1,itemToRenderItem:function(a,b){return this.owner?this.owner.itemToRenderItem(a,b):{id:b.getIdentity(a),
summary:a[this.summaryAttr],startTime:this.decodeDate&&this.decodeDate(a[this.startTimeAttr])||this.newDate(a[this.startTimeAttr],this.dateClassObj),endTime:this.decodeDate&&this.decodeDate(a[this.endTimeAttr])||this.newDate(a[this.endTimeAttr],this.dateClassObj),allDay:null!=a[this.allDayAttr]?a[this.allDayAttr]:!1,cssClass:this.cssClassFunc?this.cssClassFunc(a):null}},renderItemToItem:function(a,b){if(this.owner)return this.owner.renderItemToItem(a,b);var c={};c[b.idProperty]=a.id;c[this.summaryAttr]=
a.summary;c[this.startTimeAttr]=this.encodeDate&&this.encodeDate(a.startTime)||a.startTime;c[this.endTimeAttr]=this.encodeDate&&this.encodeDate(a.endTime)||a.endTime;return d.mixin(b.get(a.id),c)},_computeVisibleItems:function(a){var b=a.startTime,c=a.endTime;if(this.items)a.items=h.filter(this.items,function(d){return this.isOverlapping(a,d.startTime,d.endTime,b,c)},this)},_initItems:function(a){this.set("items",a);return a},_refreshItemsRendering:function(){},_updateItems:function(a,b,c){var f=
!0,e=null,a=this.itemToRenderItem(a,this.store);-1!=b?c!=b?(this.items.splice(b,1),this.setItemSelected&&this.isItemSelected(a)&&(this.setItemSelected(a,!1),this.dispatchChange(a,this.get("selectedItem"),null,null))):(e=this.items[b],b=this.dateModule,f=0!=b.compare(a.startTime,e.startTime)||0!=b.compare(a.endTime,e.endTime),d.mixin(e,a)):-1!=c&&this.items.splice(c,0,a);f?this._refreshItemsRendering():this.updateRenderers(e)},_setStoreAttr:function(a){this.displayedItemsInvalidated=!0;var b;if(this._observeHandler)this._observeHandler.remove(),
this._observeHandler=null;if(a){b=a.query(this.query);if(b.observe)this._observeHandler=b.observe(d.hitch(this,this._updateItems),!0);b=b.map(d.hitch(this,function(b){return this.itemToRenderItem(b,a)}));b=j(b,d.hitch(this,this._initItems))}else b=this._initItems([]);this._set("store",a);return b}})});