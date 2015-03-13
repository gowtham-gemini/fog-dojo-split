/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/request/watch","./util,../errors/RequestTimeoutError,../errors/CancelError,../_base/array,../_base/window,../has!host-browser?dom-addeventlistener?:../on:".split(","),function(n,j,k,l,e,h){function i(){for(var m=+new Date,d=0,b;d<c.length&&(b=c[d]);d++){var f=b.response,e=f.options;if(b.isCanceled&&b.isCanceled()||b.isValid&&!b.isValid(f))c.splice(d--,1),a._onAction&&a._onAction();else if(b.isReady&&b.isReady(f))c.splice(d--,1),b.handleResponse(f),a._onAction&&a._onAction();else if(b.startTime&&
b.startTime+(e.timeout||0)<m)c.splice(d--,1),b.cancel(new j("Timeout exceeded",f)),a._onAction&&a._onAction()}a._onInFlight&&a._onInFlight(b);c.length||(clearInterval(g),g=null)}function a(a){if(a.response.options.timeout)a.startTime=+new Date;a.isFulfilled()||(c.push(a),g||(g=setInterval(i,50)),a.response.options.sync&&i())}var g=null,c=[];a.cancelAll=function(){try{l.forEach(c,function(a){try{a.cancel(new k("All requests canceled."))}catch(b){}})}catch(a){}};e&&h&&e.doc.attachEvent&&h(e.global,
"unload",function(){a.cancelAll()});return a});