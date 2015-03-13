/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/aspect",[],function(){function l(h,c,f,i){var d=h[c],g="around"==c,a;if(g){var m=f(function(){return d.advice(this,arguments)});a={remove:function(){a.cancelled=!0},advice:function(e,b){return a.cancelled?d.advice(e,b):m.apply(e,b)}}}else a={remove:function(){var e=a.previous,b=a.next;if(!b&&!e)delete h[c];else if(e?e.next=b:h[c]=b,b)b.previous=e},id:k++,advice:f,receiveArguments:i};if(d&&!g)if("after"==c){for(f=d;f;)d=f,f=f.next;d.next=a;a.previous=d}else{if("before"==c)h[c]=a,a.next=
d,d.previous=a}else h[c]=a;return a}function j(h){return function(c,f,i,d){var g=c[f],a;if(!g||g.target!=c){c[f]=a=function(){for(var c=k,e=arguments,b=a.before;b;)e=b.advice.apply(this,e)||e,b=b.next;if(a.around)var d=a.around.advice(this,e);for(b=a.after;b&&b.id<c;){if(b.receiveArguments)var f=b.advice.apply(this,e),d=void 0===f?d:f;else d=b.advice.call(this,d,e);b=b.next}return d};if(g)a.around={advice:function(a,c){return g.apply(a,c)}};a.target=c}c=l(a||g,h,i,d);i=null;return c}}var k=0,n=j("after"),
o=j("before"),p=j("around");return{before:o,around:p,after:n}});