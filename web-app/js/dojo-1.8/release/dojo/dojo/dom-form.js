/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dom-form",["./_base/lang","./dom","./io-query","./json"],function(m,l,n,o){var g={fieldToObject:function(a){var c=null;if(a=l.byId(a)){var b=a.name,f=(a.type||"").toLowerCase();if(b&&f&&!a.disabled)if("radio"==f||"checkbox"==f){if(a.checked)c=a.value}else if(a.multiple){c=[];for(a=[a.firstChild];a.length;)for(b=a.pop();b;b=b.nextSibling)if(1==b.nodeType&&"option"==b.tagName.toLowerCase())b.selected&&c.push(b.value);else{b.nextSibling&&a.push(b.nextSibling);b.firstChild&&a.push(b.firstChild);
break}}else c=a.value}return c},toObject:function(a){for(var c={},a=l.byId(a).elements,b=0,f=a.length;b<f;++b){var d=a[b],e=d.name,i=(d.type||"").toLowerCase();if(e&&i&&0>"file|submit|image|reset|button".indexOf(i)&&!d.disabled){var j=c,k=e,d=g.fieldToObject(d);if(null!==d){var h=j[k];"string"==typeof h?j[k]=[h,d]:m.isArray(h)?h.push(d):j[k]=d}if("image"==i)c[e+".x"]=c[e+".y"]=c[e].x=c[e].y=0}}return c},toQuery:function(a){return n.objectToQuery(g.toObject(a))},toJson:function(a,c){return o.stringify(g.toObject(a),
null,c?4:0)}};return g});