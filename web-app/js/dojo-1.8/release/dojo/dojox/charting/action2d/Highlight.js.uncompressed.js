//>>built
define("dojox/charting/action2d/Highlight","dojo/_base/kernel,dojo/_base/lang,dojo/_base/declare,dojo/_base/Color,dojo/_base/connect,dojox/color/_base,./PlotAction,dojo/fx/easing,dojox/gfx/fx".split(","),function(q,h,i,j,k,e,l,m,n){var o=function(a){return function(){return a}},p=function(a){a=(new e.Color(a)).toHsl();0==a.s?a.l=50>a.l?100:0:(a.s=100,a.l=50>a.l?75:75<a.l?50:a.l-50>75-a.l?50:75);return e.fromHsl(a)};return i("dojox.charting.action2d.Highlight",l,{defaultParams:{duration:400,easing:m.backOut},
optionalParams:{highlight:"red"},constructor:function(a,c,d){this.colorFun=(a=d&&d.highlight)?h.isFunction(a)?a:o(a):p;this.connect()},process:function(a){if(a.shape&&a.type in this.overOutEvents){var c=a.run.name,d=a.index,b;c in this.anim?b=this.anim[c][d]:this.anim[c]={};if(b)b.action.stop(!0);else{b=a.shape.getFill();if(!b||!(b instanceof j))return;this.anim[c][d]=b={start:b,end:this.colorFun(b)}}var f=b.start,g=b.end;if("onmouseout"==a.type)var e=f,f=g,g=e;b.action=n.animateFill({shape:a.shape,
duration:this.duration,easing:this.easing,color:{start:f,end:g}});"onmouseout"==a.type&&k.connect(b.action,"onEnd",this,function(){this.anim[c]&&delete this.anim[c][d]});b.action.play()}}})});