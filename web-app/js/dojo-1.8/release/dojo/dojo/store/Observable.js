/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/store/Observable",["../_base/kernel","../_base/lang","../_base/Deferred","../_base/array"],function(c,g,m,p){c=function(b){function c(a,r){var d=b[a];d&&(b[a]=function(b){if(i)return d.apply(this,arguments);i=!0;try{var a=d.apply(this,arguments);m.when(a,function(a){r("object"==typeof a&&a||b)});return a}finally{i=!1}})}var k=[],q=0,b=g.delegate(b);b.notify=function(a,b){q++;for(var d=k.slice(),c=0,j=d.length;c<j;c++)d[c](a,b)};var t=b.query;b.query=function(a,c){var c=c||{},d=t.apply(this,
arguments);if(d&&d.forEach){var i=g.mixin({},c);delete i.start;delete i.count;var j=b.queryEngine&&b.queryEngine(a,i),s=q,n=[],o;d.observe=function(a,i){1==n.push(a)&&k.push(o=function(a,g){m.when(d,function(e){var d=e.length!=c.count,f,k;if(++s!=q)throw Error("Query is out of date, you must observe() the query prior to any data modifications");var m,l=-1,h=-1;if(void 0!==g)for(f=0,k=e.length;f<k;f++){var o=e[f];if(b.getIdentity(o)==g){m=o;l=f;(j||!a)&&e.splice(f,1);break}}if(j){if(a&&(j.matches?
j.matches(a):j([a]).length))f=-1<l?l:e.length,e.splice(f,0,a),h=p.indexOf(j(e),a),e.splice(f,1),c.start&&0==h||!d&&h==e.length?h=-1:e.splice(h,0,a)}else a&&(void 0!==g?h=l:c.start||(h=b.defaultIndex||0,e.splice(h,0,a)));if((-1<l||-1<h)&&(i||!j||l!=h)){d=n.slice();for(f=0;e=d[f];f++)e(a||m,l,h)}})});var g={};g.remove=g.cancel=function(){var b=p.indexOf(n,a);-1<b&&(n.splice(b,1),n.length||k.splice(p.indexOf(k,o),1))};return g}}return d};var i;c("put",function(a){b.notify(a,b.getIdentity(a))});c("add",
function(a){b.notify(a)});c("remove",function(a){b.notify(void 0,a)});return b};g.setObject("dojo.store.Observable",c);return c});