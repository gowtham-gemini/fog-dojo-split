//>>built
require({cache:{"url:dijit/templates/Tooltip.html":'<div class="dijitTooltip dijitTooltipLeft" id="dojoTooltip"\n\t><div class="dijitTooltipContainer dijitTooltipContents" data-dojo-attach-point="containerNode" role=\'alert\'></div\n\t><div class="dijitTooltipConnector" data-dojo-attach-point="connectorNode"></div\n></div>\n'}});require({cache:{"url:dijit/templates/Tooltip.html":'<div class="dijitTooltip dijitTooltipLeft" id="dojoTooltip"\n\t><div class="dijitTooltipContainer dijitTooltipContents" data-dojo-attach-point="containerNode" role=\'alert\'></div\n\t><div class="dijitTooltipConnector" data-dojo-attach-point="connectorNode"></div\n></div>\n'}});
define("dijit/Tooltip","dojo/_base/array,dojo/_base/declare,dojo/_base/fx,dojo/dom,dojo/dom-class,dojo/dom-geometry,dojo/dom-style,dojo/_base/lang,dojo/mouse,dojo/on,dojo/sniff,./_base/manager,./place,./_Widget,./_TemplatedMixin,./BackgroundIframe,dojo/text!./templates/Tooltip.html,./main".split(","),function(b,n,o,p,t,l,u,d,q,i,m,v,w,r,x,y,z,k){var s=n("dijit._MasterTooltip",[r,x],{duration:v.defaultDuration,templateString:z,postCreate:function(){this.ownerDocumentBody.appendChild(this.domNode);
this.bgIframe=new y(this.domNode);this.fadeIn=o.fadeIn({node:this.domNode,duration:this.duration,onEnd:d.hitch(this,"_onShow")});this.fadeOut=o.fadeOut({node:this.domNode,duration:this.duration,onEnd:d.hitch(this,"_onHide")})},show:function(a,e,h,f,j){if(!this.aroundNode||!(this.aroundNode===e&&this.containerNode.innerHTML==a))if("playing"==this.fadeOut.status())this._onDeck=arguments;else{this.containerNode.innerHTML=a;j&&this.set("textDir",j);this.containerNode.align=f?"right":"left";var g=w.around(this.domNode,
e,h&&h.length?h:c.defaultPosition,!f,d.hitch(this,"orient")),b=g.aroundNodePos;"M"==g.corner.charAt(0)&&"M"==g.aroundCorner.charAt(0)?(this.connectorNode.style.top=b.y+(b.h-this.connectorNode.offsetHeight>>1)-g.y+"px",this.connectorNode.style.left=""):"M"==g.corner.charAt(1)&&"M"==g.aroundCorner.charAt(1)?this.connectorNode.style.left=b.x+(b.w-this.connectorNode.offsetWidth>>1)-g.x+"px":(this.connectorNode.style.left="",this.connectorNode.style.top="");u.set(this.domNode,"opacity",0);this.fadeIn.play();
this.isShowingNow=!0;this.aroundNode=e}},orient:function(a,e,b,f,c){this.connectorNode.style.top="";var g=f.h,f=f.w;a.className="dijitTooltip "+{"MR-ML":"dijitTooltipRight","ML-MR":"dijitTooltipLeft","TM-BM":"dijitTooltipAbove","BM-TM":"dijitTooltipBelow","BL-TL":"dijitTooltipBelow dijitTooltipABLeft","TL-BL":"dijitTooltipAbove dijitTooltipABLeft","BR-TR":"dijitTooltipBelow dijitTooltipABRight","TR-BR":"dijitTooltipAbove dijitTooltipABRight","BR-BL":"dijitTooltipRight","BL-BR":"dijitTooltipLeft"}[e+
"-"+b];this.domNode.style.width="auto";var d=l.position(this.domNode);9==m("ie")&&(d.w+=2);var i=Math.min(Math.max(f,1),d.w);l.setMarginBox(this.domNode,{w:i});"B"==b.charAt(0)&&"B"==e.charAt(0)?(a=l.position(a),e=this.connectorNode.offsetHeight,a.h>g?(this.connectorNode.style.top=g-(c.h+e>>1)+"px",this.connectorNode.style.bottom=""):(this.connectorNode.style.bottom=Math.min(Math.max(c.h/2-e/2,0),a.h-e)+"px",this.connectorNode.style.top="")):(this.connectorNode.style.top="",this.connectorNode.style.bottom=
"");return Math.max(0,d.w-f)},_onShow:function(){if(m("ie"))this.domNode.style.filter=""},hide:function(a){if(this._onDeck&&this._onDeck[1]==a)this._onDeck=null;else if(this.aroundNode===a)this.fadeIn.stop(),this.isShowingNow=!1,this.aroundNode=null,this.fadeOut.play()},_onHide:function(){this.domNode.style.cssText="";this.containerNode.innerHTML="";if(this._onDeck)this.show.apply(this,this._onDeck),this._onDeck=null},_setAutoTextDir:function(a){this.applyTextDir(a,m("ie")?a.outerText:a.textContent);
b.forEach(a.children,function(a){this._setAutoTextDir(a)},this)},_setTextDirAttr:function(a){this._set("textDir",a);"auto"==a?this._setAutoTextDir(this.containerNode):this.containerNode.dir=this.textDir}});k.showTooltip=function(a,e,h,f,d){h&&(h=b.map(h,function(a){return{after:"after-centered",before:"before-centered"}[a]||a}));if(!c._masterTT)k._masterTT=c._masterTT=new s;return c._masterTT.show(a,e,h,f,d)};k.hideTooltip=function(a){return c._masterTT&&c._masterTT.hide(a)};var c=n("dijit.Tooltip",
r,{label:"",showDelay:400,connectId:[],position:[],selector:"",_setConnectIdAttr:function(a){b.forEach(this._connections||[],function(a){b.forEach(a,function(a){a.remove()})},this);this._connectIds=b.filter(d.isArrayLike(a)?a:a?[a]:[],function(a){return p.byId(a,this.ownerDocument)},this);this._connections=b.map(this._connectIds,function(a){var a=p.byId(a,this.ownerDocument),b=this.selector,c=b?function(a){return i.selector(b,a)}:function(a){return a},j=this;return[i(a,c(q.enter),function(){j._onHover(this)}),
i(a,c("focusin"),function(){j._onHover(this)}),i(a,c(q.leave),d.hitch(j,"_onUnHover")),i(a,c("focusout"),d.hitch(j,"_onUnHover"))]},this);this._set("connectId",a)},addTarget:function(a){a=a.id||a;-1==b.indexOf(this._connectIds,a)&&this.set("connectId",this._connectIds.concat(a))},removeTarget:function(a){a=b.indexOf(this._connectIds,a.id||a);0<=a&&(this._connectIds.splice(a,1),this.set("connectId",this._connectIds))},buildRendering:function(){this.inherited(arguments);t.add(this.domNode,"dijitTooltipData")},
startup:function(){this.inherited(arguments);var a=this.connectId;b.forEach(d.isArrayLike(a)?a:[a],this.addTarget,this)},getContent:function(){return this.label||this.domNode.innerHTML},_onHover:function(a){if(!this._showTimer)this._showTimer=this.defer(function(){this.open(a)},this.showDelay)},_onUnHover:function(){this._showTimer&&(this._showTimer.remove(),delete this._showTimer);this.close()},open:function(a){this._showTimer&&(this._showTimer.remove(),delete this._showTimer);var b=this.getContent(a);
if(b)c.show(b,a,this.position,!this.isLeftToRight(),this.textDir),this._connectNode=a,this.onShow(a,this.position)},close:function(){this._connectNode&&(c.hide(this._connectNode),delete this._connectNode,this.onHide());this._showTimer&&(this._showTimer.remove(),delete this._showTimer)},onShow:function(){},onHide:function(){},destroy:function(){this.close();b.forEach(this._connections||[],function(a){b.forEach(a,function(a){a.remove()})},this);this.inherited(arguments)}});c._MasterTooltip=s;c.show=
k.showTooltip;c.hide=k.hideTooltip;c.defaultPosition=["after-centered","before-centered"];return c});