/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/store/util/QueryResults",["../../_base/array","../../_base/lang","../../_base/Deferred"],function(e,f,g){var d=function(a){function b(c){a[c]||(a[c]=function(){var b=arguments;return g.when(a,function(a){Array.prototype.unshift.call(b,a);return d(e[c].apply(e,b))})})}if(!a)return a;a.then&&(a=f.delegate(a));b("forEach");b("filter");b("map");if(!a.total)a.total=g.when(a,function(a){return a.length});return a};f.setObject("dojo.store.util.QueryResults",d);return d});