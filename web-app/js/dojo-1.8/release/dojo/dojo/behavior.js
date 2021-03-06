/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/behavior","./_base/kernel,./_base/lang,./_base/array,./_base/connect,./query,./ready".split(","),function(d,g,k,h,l,j){d.deprecated("dojo.behavior","Use dojo/on with event delegation (on.selector())");d.behavior=new function(){function d(a,b){a[b]||(a[b]=[]);return a[b]}function i(a,b,f){var e={},c;for(c in a)"undefined"==typeof e[c]&&(f?f.call(b,a[c],c):b(a[c],c))}var j=0;this._behaviors={};this.add=function(a){i(a,this,function(b,a){var e=d(this._behaviors,a);if("number"!=typeof e.id)e.id=
j++;var c=[];e.push(c);if(g.isString(b)||g.isFunction(b))b={found:b};i(b,function(a,b){d(c,b).push(a)})})};var m=function(a,b,f){g.isString(b)?"found"==f?h.publish(b,[a]):h.connect(a,f,function(){h.publish(b,arguments)}):g.isFunction(b)&&("found"==f?b(a):h.connect(a,f,b))};this.apply=function(){i(this._behaviors,function(a,b){l(b).forEach(function(b){var e=0,c="_dj_behavior_"+a.id;if("number"==typeof b[c]&&(e=b[c],e==a.length))return;for(var d;d=a[e];e++)i(d,function(a,c){g.isArray(a)&&k.forEach(a,
function(a){m(b,a,c)})});b[c]=a.length})})}};j(d.behavior,"apply");return d.behavior});