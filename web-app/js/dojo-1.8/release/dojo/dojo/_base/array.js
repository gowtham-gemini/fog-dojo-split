/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/_base/array",["./kernel","../has","./lang"],function(n,q,o){function j(a){return i[a]=new Function("item","index","array",a)}function l(a){var e=!a;return function(f,b,c){var g=0,d=f&&f.length||0,h;d&&"string"==typeof f&&(f=f.split(""));"string"==typeof b&&(b=i[b]||j(b));if(c)for(;g<d;++g){if(h=!b.call(c,f[g],g,f),a^h)return!h}else for(;g<d;++g)if(h=!b(f[g],g,f),a^h)return!h;return e}}function m(a){var e=1,f=0,b=0;a||(e=f=b=-1);return function(c,g,d,h){if(h&&0<e)return k.lastIndexOf(c,
g,d);var h=c&&c.length||0,i=a?h+b:f;d===p?d=a?f:h+b:0>d?(d=h+d,0>d&&(d=f)):d=d>=h?h+b:d;for(h&&"string"==typeof c&&(c=c.split(""));d!=i;d+=e)if(c[d]==g)return d;return-1}}var i={},p,k={every:l(!1),some:l(!0),indexOf:m(!0),lastIndexOf:m(!1),forEach:function(a,e,f){var b=0,c=a&&a.length||0;c&&"string"==typeof a&&(a=a.split(""));"string"==typeof e&&(e=i[e]||j(e));if(f)for(;b<c;++b)e.call(f,a[b],b,a);else for(;b<c;++b)e(a[b],b,a)},map:function(a,e,f,b){var c=0,g=a&&a.length||0,b=new (b||Array)(g);g&&
"string"==typeof a&&(a=a.split(""));"string"==typeof e&&(e=i[e]||j(e));if(f)for(;c<g;++c)b[c]=e.call(f,a[c],c,a);else for(;c<g;++c)b[c]=e(a[c],c,a);return b},filter:function(a,e,f){var b=0,c=a&&a.length||0,g=[],d;c&&"string"==typeof a&&(a=a.split(""));"string"==typeof e&&(e=i[e]||j(e));if(f)for(;b<c;++b)d=a[b],e.call(f,d,b,a)&&g.push(d);else for(;b<c;++b)d=a[b],e(d,b,a)&&g.push(d);return g},clearCache:function(){i={}}};o.mixin(n,k);return k});