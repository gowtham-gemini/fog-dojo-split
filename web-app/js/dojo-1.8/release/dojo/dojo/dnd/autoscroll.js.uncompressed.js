/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dnd/autoscroll","../_base/lang,../sniff,../_base/window,../dom-geometry,../dom-style,../window".split(","),function(s,n,k,p,t,o){var a={};s.setObject("dojo.dnd.autoscroll",a);a.getViewport=o.getBox;a.V_TRIGGER_AUTOSCROLL=32;a.H_TRIGGER_AUTOSCROLL=32;a.V_AUTOSCROLL_VALUE=16;a.H_AUTOSCROLL_VALUE=16;var l,e=k.doc,q=Infinity,r=Infinity;a.autoScrollStart=function(a){e=a;l=o.getBox(e);a=k.body(e).parentNode;q=Math.max(a.scrollHeight-l.h,0);r=Math.max(a.scrollWidth-l.w,0)};a.autoScroll=function(i){var f=
l||o.getBox(e),j=k.body(e).parentNode,b=0,c=0;i.clientX<a.H_TRIGGER_AUTOSCROLL?b=-a.H_AUTOSCROLL_VALUE:i.clientX>f.w-a.H_TRIGGER_AUTOSCROLL&&(b=Math.min(a.H_AUTOSCROLL_VALUE,r-j.scrollLeft));i.clientY<a.V_TRIGGER_AUTOSCROLL?c=-a.V_AUTOSCROLL_VALUE:i.clientY>f.h-a.V_TRIGGER_AUTOSCROLL&&(c=Math.min(a.V_AUTOSCROLL_VALUE,q-j.scrollTop));window.scrollBy(b,c)};a._validNodes={div:1,p:1,td:1};a._validOverflow={auto:1,scroll:1};a.autoScrollNodes=function(i){for(var f,j,b,c,g,h,e=0,m=0,d=i.target;d;){if(1==
d.nodeType&&d.tagName.toLowerCase()in a._validNodes){b=t.getComputedStyle(d);c=b.overflow.toLowerCase()in a._validOverflow;g=b.overflowX.toLowerCase()in a._validOverflow;h=b.overflowY.toLowerCase()in a._validOverflow;if(c||g||h)f=p.getContentBox(d,b),j=p.position(d,!0);if(c||g){b=Math.min(a.H_TRIGGER_AUTOSCROLL,f.w/2);g=i.pageX-j.x;if(n("webkit")||n("opera"))g+=k.body().scrollLeft;e=0;0<g&&g<f.w&&(g<b?e=-b:g>f.w-b&&(e=b),d.scrollLeft+=e)}if(c||h){c=Math.min(a.V_TRIGGER_AUTOSCROLL,f.h/2);h=i.pageY-
j.y;if(n("webkit")||n("opera"))h+=k.body().scrollTop;m=0;0<h&&h<f.h&&(h<c?m=-c:h>f.h-c&&(m=c),d.scrollTop+=m)}if(e||m)return}try{d=d.parentNode}catch(l){d=null}}a.autoScroll(i)};return a});