/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/store/util/SimpleQueryEngine",["../../_base/array"],function(i){return function(a,b){function d(c){var c=i.filter(c,a),e=b&&b.sort;e&&c.sort("function"==typeof e?e:function(c,a){for(var b,f=0;b=e[f];f++){var g=c[b.attribute],d=a[b.attribute];if(g!=d)return!!b.descending==(null==g||g>d)?-1:1}return 0});if(b&&(b.start||b.count)){var f=c.length,c=c.slice(b.start||0,(b.start||0)+(b.count||Infinity));c.total=f}return c}switch(typeof a){default:throw Error("Can not query with a "+typeof a);
case "object":case "undefined":var h=a,a=function(c){for(var b in h){var a=h[b];if(a&&a.test){if(!a.test(c[b],c))return!1}else if(a!=c[b])return!1}return!0};break;case "string":if(!this[a])throw Error("No filter function "+a+" was found in store");a=this[a];case "function":}d.matches=a;return d}});