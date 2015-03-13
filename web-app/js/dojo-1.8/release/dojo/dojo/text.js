/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/text",["./_base/kernel","require","./has","./_base/xhr"],function(g,o,q,p){var j;j=function(a,c,b){p("GET",{url:a,sync:!!c,load:b,headers:g.config.textPluginHeaders||{}})};var e={},k=function(a){if(a){var a=a.replace(/^\s*<\?xml(\s)+version=[\'\"](\d)*.(\d)*[\'\"](\s)*\?>/im,""),c=a.match(/<body[^>]*>\s*([\s\S]+)\s*<\/body>/im);c&&(a=c[1])}else a="";return a},n={},i={};g.cache=function(a,c,b){var d;"string"==typeof a?/\//.test(a)?(d=a,b=c):d=o.toUrl(a.replace(/\./g,"/")+(c?"/"+c:"")):
(d=a+"",b=c);a=void 0!=b&&"string"!=typeof b?b.value:b;b=b&&b.sanitize;if("string"==typeof a)return e[d]=a,b?k(a):a;if(null===a)return delete e[d],null;d in e||j(d,!0,function(a){e[d]=a});return b?k(e[d]):e[d]};return{dynamic:!0,normalize:function(a,c){var b=a.split("!"),d=b[0];return(/^\./.test(d)?c(d):d)+(b[1]?"!"+b[1]:"")},load:function(a,c,b){var a=a.split("!"),d=1<a.length,l=a[0],f=c.toUrl(a[0]),a="url:"+f,h=n,m=function(a){b(d?k(a):a)};l in e?h=e[l]:a in c.cache?h=c.cache[a]:f in e&&(h=e[f]);
if(h===n)if(i[f])i[f].push(m);else{var g=i[f]=[m];j(f,!c.async,function(a){e[l]=e[f]=a;for(var b=0;b<g.length;)g[b++](a);delete i[f]})}else m(h)}}});