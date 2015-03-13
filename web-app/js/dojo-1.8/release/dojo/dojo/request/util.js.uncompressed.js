/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/request/util","exports,../errors/RequestError,../errors/CancelError,../Deferred,../io-query,../_base/array,../_base/lang".split(","),function(f,m,j,n,k,o,h){function p(b){return l(b)}f.deepCopy=function(b,c){for(var d in c){var e=b[d],a=c[d];e!==a&&(e&&"object"===typeof e&&a&&"object"===typeof a?f.deepCopy(e,a):b[d]=a)}return b};f.deepCreate=function(b,c){var c=c||{},d=h.delegate(b),e,a;for(e in b)(a=b[e])&&"object"===typeof a&&(d[e]=f.deepCreate(a,c[e]));return f.deepCopy(d,c)};var l=
Object.freeze||function(b){return b};f.deferred=function(b,c,d,e,a,i){var g=new n(function(a){c&&c(g,b);return!a||!(a instanceof m)&&!(a instanceof j)?new j("Request canceled",b):a});g.response=b;g.isValid=d;g.isReady=e;g.handleResponse=a;d=g.then(p).otherwise(function(a){a.response=b;throw a;});f.notify&&d.then(h.hitch(f.notify,"emit","load"),h.hitch(f.notify,"emit","error"));e=d.then(function(a){return a.data||a.text});d=l(h.delegate(e,{response:d}));i&&g.then(function(a){i.call(g,a)},function(a){i.call(g,
b,a)});g.promise=d;g.then=d.then;return g};f.addCommonMethods=function(b,c){o.forEach(c||["GET","POST","PUT","DELETE"],function(d){b[("DELETE"===d?"DEL":d).toLowerCase()]=function(c,a){a=h.delegate(a||{});a.method=d;return b(c,a)}})};f.parseArgs=function(b,c,d){var e=c.data,a=c.query;if(e&&!d&&"object"===typeof e)c.data=k.objectToQuery(e);a?("object"===typeof a&&(a=k.objectToQuery(a)),c.preventCache&&(a+=(a?"&":"")+"request.preventCache="+ +new Date)):c.preventCache&&(a="request.preventCache="+ +new Date);
b&&a&&(b+=(~b.indexOf("?")?"&":"?")+a);return{url:b,options:c,getHeader:function(){return null}}};f.checkStatus=function(b){b=b||0;return 200<=b&&300>b||304===b||1223===b||!b}});