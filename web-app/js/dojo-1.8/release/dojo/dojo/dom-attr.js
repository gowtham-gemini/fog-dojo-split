/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dom-attr","exports,./sniff,./_base/lang,./dom,./dom-style,./dom-prop".split(","),function(f,m,l,g,n,h){function i(a,c){var b=a.getAttributeNode&&a.getAttributeNode(c);return b&&b.specified}var k={innerHTML:1,className:1,htmlFor:m("ie"),value:1},j={classname:"class",htmlfor:"for",tabindex:"tabIndex",readonly:"readOnly"};f.has=function(a,c){var b=c.toLowerCase();return k[h.names[b]||c]||i(g.byId(a),j[b]||c)};f.get=function(a,c){var a=g.byId(a),b=c.toLowerCase(),d=h.names[b]||c,e=a[d];if(k[d]&&
"undefined"!=typeof e||"href"!=d&&("boolean"==typeof e||l.isFunction(e)))return e;b=j[b]||c;return i(a,b)?a.getAttribute(b):null};f.set=function(a,c,b){a=g.byId(a);if(2==arguments.length){for(var d in c)f.set(a,d,c[d]);return a}d=c.toLowerCase();var e=h.names[d]||c,i=k[e];if("style"==e&&"string"!=typeof b)return n.set(a,b),a;if(i||"boolean"==typeof b||l.isFunction(b))return h.set(a,c,b);a.setAttribute(j[d]||c,b);return a};f.remove=function(a,c){g.byId(a).removeAttribute(j[c.toLowerCase()]||c)};f.getNodeProp=
function(a,c){var a=g.byId(a),b=c.toLowerCase(),d=h.names[b]||c;if(d in a&&"href"!=d)return a[d];b=j[b]||c;return i(a,b)?a.getAttribute(b):null}});