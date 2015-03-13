/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dom-prop","exports,./_base/kernel,./sniff,./_base/lang,./dom,./dom-style,./dom-construct,./_base/connect".split(","),function(f,h,n,o,i,p,j,k){var g={},q=0,l=h._scopeName+"attrid";f.names={"class":"className","for":"htmlFor",tabindex:"tabIndex",readonly:"readOnly",colspan:"colSpan",frameborder:"frameBorder",rowspan:"rowSpan",valuetype:"valueType"};f.get=function(a,d){var a=i.byId(a),c=d.toLowerCase();return a[f.names[c]||d]};f.set=function(a,d,c){a=i.byId(a);if(2==arguments.length&&"string"!=
typeof d){for(var b in d)f.set(a,b,d[b]);return a}b=d.toLowerCase();b=f.names[b]||d;if("style"==b&&"string"!=typeof c)return p.set(a,c),a;if("innerHTML"==b)return n("ie")&&a.tagName.toLowerCase()in{col:1,colgroup:1,table:1,tbody:1,tfoot:1,thead:1,tr:1,title:1}?(j.empty(a),a.appendChild(j.toDom(c,a.ownerDocument))):a[b]=c,a;if(o.isFunction(c)){var e=a[l];e||(e=q++,a[l]=e);g[e]||(g[e]={});var m=g[e][b];if(m)k.disconnect(m);else try{delete a[b]}catch(h){}c?g[e][b]=k.connect(a,b,c):a[b]=null;return a}a[b]=
c;return a}});