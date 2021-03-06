/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/touch","./_base/kernel,./_base/lang,./aspect,./dom,./on,./has,./mouse,./ready,./_base/window".split(","),function(i,j,a,k,c,l,f,m,d){function e(g){return function(b,a){return c(b,g,a)}}var a=l("touch"),h,b;a&&(m(function(){b=d.body();d.doc.addEventListener("touchstart",function(g){var a=b;b=g.target;c.emit(a,"dojotouchout",{target:a,relatedTarget:b,bubbles:!0});c.emit(b,"dojotouchover",{target:b,relatedTarget:a,bubbles:!0})},!0);c(d.doc,"touchmove",function(a){if((a=d.doc.elementFromPoint(a.pageX-
d.global.pageXOffset,a.pageY-d.global.pageYOffset))&&b!==a)c.emit(b,"dojotouchout",{target:b,relatedTarget:a,bubbles:!0}),c.emit(a,"dojotouchover",{target:a,relatedTarget:b,bubbles:!0}),b=a})}),h=function(a,e){return c(d.doc,"touchmove",function(c){(a===d.doc||k.isDescendant(b,a))&&e.call(this,j.mixin({},c,{target:b}))})});f={press:e(a?"touchstart":"mousedown"),move:a?h:e("mousemove"),release:e(a?"touchend":"mouseup"),cancel:a?e("touchcancel"):f.leave,over:e(a?"dojotouchover":"mouseover"),out:e(a?
"dojotouchout":"mouseout"),enter:f._eventHandler(a?"dojotouchover":"mouseover"),leave:f._eventHandler(a?"dojotouchout":"mouseout")};return i.touch=f});