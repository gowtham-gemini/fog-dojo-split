/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dnd/Mover","../_base/array,../_base/declare,../_base/event,../_base/lang,../sniff,../_base/window,../dom,../dom-geometry,../dom-style,../Evented,../on,../touch,./common,./autoscroll".split(","),function(l,m,e,g,j,n,o,h,p,q,c,i,r,k){return m("dojo.dnd.Mover",[q],{constructor:function(a,b,d){this.node=o.byId(a);this.marginBox={l:b.pageX,t:b.pageY};this.mouseButton=b.button;b=this.host=d;a=a.ownerDocument;this.events=[c(a,i.move,g.hitch(this,"onFirstMove")),c(a,i.move,g.hitch(this,"onMouseMove")),
c(a,i.release,g.hitch(this,"onMouseUp")),c(a,"dragstart",e.stop),c(a.body,"selectstart",e.stop)];k.autoScrollStart(a);if(b&&b.onMoveStart)b.onMoveStart(this)},onMouseMove:function(a){k.autoScroll(a);var b=this.marginBox;this.host.onMove(this,{l:b.l+a.pageX,t:b.t+a.pageY},a);e.stop(a)},onMouseUp:function(a){(j("webkit")&&j("mac")&&2==this.mouseButton?0==a.button:this.mouseButton==a.button)&&this.destroy();e.stop(a)},onFirstMove:function(a){var b=this.node.style,d,c=this.host;switch(b.position){case "relative":case "absolute":d=
Math.round(parseFloat(b.left))||0;b=Math.round(parseFloat(b.top))||0;break;default:b.position="absolute";b=h.getMarginBox(this.node);d=n.doc.body;var f=p.getComputedStyle(d),e=h.getMarginBox(d,f),f=h.getContentBox(d,f);d=b.l-(f.l-e.l);b=b.t-(f.t-e.t)}this.marginBox.l=d-this.marginBox.l;this.marginBox.t=b-this.marginBox.t;if(c&&c.onFirstMove)c.onFirstMove(this,a);this.events.shift().remove()},destroy:function(){l.forEach(this.events,function(a){a.remove()});var a=this.host;if(a&&a.onMoveStop)a.onMoveStop(this);
this.events=this.node=this.host=null}})});