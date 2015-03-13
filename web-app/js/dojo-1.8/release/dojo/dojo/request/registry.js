/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/request/registry",["require","../_base/array","./default!platform","./util"],function(h,i,g,j){function a(b,d){for(var c=e.slice(0),f=0,a;a=c[f++];)if(a(b,d))return a.request.call(null,b,d);return g.apply(null,arguments)}function k(b,a){var c;a?(c=b.test?function(a){return b.test(a)}:b.apply&&b.call?function(){return b.apply(null,arguments)}:function(a){return a===b},c.request=a):(c=function(){return!0},c.request=b);return c}var e=[];a.register=function(a,d,c){var f=k(a,d);e[c?"unshift":
"push"](f);return{remove:function(){var a;~(a=i.indexOf(e,f))&&e.splice(a,1)}}};a.load=function(b,d,c){b?h([b],function(b){g=b;c(a)}):c(a)};j.addCommonMethods(a);return a});