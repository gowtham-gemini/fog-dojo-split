/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/request/handlers",["../json","../_base/kernel","../_base/array","../has","../selector/_loader"],function(g,h,i,c){function d(a){var b=e[a.options.handleAs];a.data=b?b(a):a.data||a.text;return a}c.add("activex","undefined"!==typeof ActiveXObject);c.add("dom-parser",function(a){return"DOMParser"in a});var f;if(c("activex")){var j=["Msxml2.DOMDocument.6.0","Msxml2.DOMDocument.4.0","MSXML2.DOMDocument.3.0","MSXML.DOMDocument"];f=function(a){var b=a.data;b&&c("dom-qsa2.1")&&!b.querySelectorAll&&
c("dom-parser")&&(b=(new DOMParser).parseFromString(a.text,"application/xml"));if(!b||!b.documentElement){var d=a.text;i.some(j,function(a){try{var c=new ActiveXObject(a);c.async=!1;c.loadXML(d);b=c}catch(e){return!1}return!0})}return b}}var e={javascript:function(a){return h.eval(a.text||"")},json:function(a){return g.parse(a.text||null)},xml:f};d.register=function(a,b){e[a]=b};return d});