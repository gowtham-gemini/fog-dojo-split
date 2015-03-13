/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dom",["./sniff","./_base/lang","./_base/window"],function(f,i,g){if(7>=f("ie"))try{document.execCommand("BackgroundImageCache",!1,!0)}catch(j){}var e={};e.byId=f("ie")?function(a,c){if("string"!=typeof a)return a;var d=c||g.doc,b=a&&d.getElementById(a);if(b&&(b.attributes.id.value==a||b.id==a))return b;d=d.all[a];if(!d||d.nodeName)d=[d];for(var e=0;b=d[e++];)if(b.attributes&&b.attributes.id&&b.attributes.id.value==a||b.id==a)return b}:function(a,c){return("string"==typeof a?(c||g.doc).getElementById(a):
a)||null};e.isDescendant=function(a,c){try{a=e.byId(a);for(c=e.byId(c);a;){if(a==c)return!0;a=a.parentNode}}catch(d){}return!1};e.setSelectable=function(a,c){a=e.byId(a);if(f("mozilla"))a.style.MozUserSelect=c?"":"none";else if(f("khtml")||f("webkit"))a.style.KhtmlUserSelect=c?"auto":"none";else if(f("ie"))for(var d=a.unselectable=c?"":"on",b=a.getElementsByTagName("*"),h=0,g=b.length;h<g;++h)b.item(h).unselectable=d};return e});