/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/has",["require","module"],function(b){var a=b.has||function(){};a.add("dom-addeventlistener",!!document.addEventListener);a.add("touch","ontouchstart"in document);a.add("device-width",screen.availWidth||innerWidth);b=document.createElement("form");a.add("dom-attributes-explicit",0==b.attributes.length);a.add("dom-attributes-specified-flag",0<b.attributes.length&&40>b.attributes.length);a.clearElement=function(a){a.innerHTML="";return a};a.normalize=function(c,b){var d=c.match(/[\?:]|[^:\?]*/g),
f=0,e=function(b){var c=d[f++];if(":"==c)return 0;if("?"==d[f++]){if(!b&&a(c))return e();e(!0);return e(b)}return c||0};return(c=e())&&b(c)};a.load=function(a,b,d){a?b([a],d):d()};return a});