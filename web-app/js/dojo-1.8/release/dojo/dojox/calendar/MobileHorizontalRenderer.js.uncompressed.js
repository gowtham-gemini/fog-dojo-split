//>>built
require({cache:{"url:dojox/calendar/templates/MobileHorizontalRenderer.html":'<div class="dojoxCalendarEvent dojoxCalendarHorizontal" onselectstart="return false;">\n\t<div class="bg" ></div>\n\t<div style="position:absolute;left:2px;bottom:2px"><span data-dojo-attach-point="beforeIcon" class="beforeIcon">\u25c4</span></div>\t\n\t<div data-dojo-attach-point="labelContainer" class="labels">\t\t\n\t\t<span data-dojo-attach-point="startTimeLabel" class="startTime"></span>\n\t\t<span data-dojo-attach-point="summaryLabel" class="summary"></span>\n\t\t<span  data-dojo-attach-point="endTimeLabel" class="endTime"></span>\n\t</div>\n\t<div style="position:absolute;right:2px;bottom:2px"><span data-dojo-attach-point="afterIcon" class="afterIcon">\u25ba</span></div>\n\t<div data-dojo-attach-point="moveHandle" class="moveHandle" ></div>\t\n\t<div data-dojo-attach-point="resizeStartHandle" class="resizeHandle resizeStartHandle"><div></div></div>\t\n\t<div data-dojo-attach-point="resizeEndHandle" class="resizeHandle resizeEndHandle"><div></div></div>\t\n</div>\n'}});
require({cache:{"url:dojox/calendar/templates/MobileHorizontalRenderer.html":'<div class="dojoxCalendarEvent dojoxCalendarHorizontal" onselectstart="return false;">\n\t<div class="bg" ></div>\n\t<div style="position:absolute;left:2px;bottom:2px"><span data-dojo-attach-point="beforeIcon" class="beforeIcon">\u25c4</span></div>\t\n\t<div data-dojo-attach-point="labelContainer" class="labels">\t\t\n\t\t<span data-dojo-attach-point="startTimeLabel" class="startTime"></span>\n\t\t<span data-dojo-attach-point="summaryLabel" class="summary"></span>\n\t\t<span  data-dojo-attach-point="endTimeLabel" class="endTime"></span>\n\t</div>\n\t<div style="position:absolute;right:2px;bottom:2px"><span data-dojo-attach-point="afterIcon" class="afterIcon">\u25ba</span></div>\n\t<div data-dojo-attach-point="moveHandle" class="moveHandle" ></div>\t\n\t<div data-dojo-attach-point="resizeStartHandle" class="resizeHandle resizeStartHandle"><div></div></div>\t\n\t<div data-dojo-attach-point="resizeEndHandle" class="resizeHandle resizeEndHandle"><div></div></div>\t\n</div>\n'}});
define("dojox/calendar/MobileHorizontalRenderer","dojo/_base/declare,dojo/dom-style,dijit/_WidgetBase,dijit/_TemplatedMixin,dojox/calendar/_RendererMixin,dojo/text!./templates/MobileHorizontalRenderer.html".split(","),function(c,b,g,h,i,j){return c("dojox.calendar.MobileHorizontalRenderer",[g,h,i],{templateString:j,_orientation:"horizontal",mobile:!0,visibilityLimits:{resizeStartHandle:50,resizeEndHandle:-1,summaryLabel:15,startTimeLabel:32,endTimeLabel:30},_displayValue:"inline",arrowPadding:12,
_isElementVisible:function(d,e,f,c){var a;a=this.isLeftToRight();"startTimeLabel"==d&&(this.labelContainer&&(a&&f||!a&&e)?b.set(this.labelContainer,"marginRight",this.arrowPadding+"px"):b.set(this.labelContainer,"marginRight",0),this.labelContainer&&(!a&&f||a&&e)?b.set(this.labelContainer,"marginLeft",this.arrowPadding+"px"):b.set(this.labelContainer,"marginLeft",0));switch(d){case "startTimeLabel":a=this.item.startTime;if(this.item.allDay||this.owner.isStartOfDay(a))return!1;break;case "endTimeLabel":if(a=
this.item.endTime,this.item.allDay||this.owner.isStartOfDay(a))return!1}return this.inherited(arguments)},postCreate:function(){this.inherited(arguments);this._applyAttributes()}})});