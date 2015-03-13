/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/ready",["./_base/kernel","./has","require","./domReady","./_base/lang"],function(a,b,j,n,k){var m=0,g,c=[],h=0,i=function(){if(m&&!h&&c.length){h=1;var a=c.shift();try{a()}finally{h=0}h=0;c.length&&g(i)}};j.on("idle",i);g=function(){j.idle()&&i()};var b=a.ready=a.addOnLoad=function(e,b,f){var d=k._toArray(arguments);"number"!=typeof e?(f=b,b=e,e=1E3):d.shift();f=f?k.hitch.apply(a,d):function(){b()};f.priority=e;for(d=0;d<c.length&&e>=c[d].priority;d++);c.splice(d,0,f);g()},l=a.config.addOnLoad;
if(l)b[k.isArray(l)?"apply":"call"](a,l);a.config.parseOnLoad&&!a.isAsync&&b(99,function(){a.parser||(a.deprecated("Add explicit require(['dojo/parser']);","","2.0"),j(["dojo/parser"]))});n(function(){m=1;a._postLoad=a.config.afterOnLoad=!0;c.length&&g(i)});return b});