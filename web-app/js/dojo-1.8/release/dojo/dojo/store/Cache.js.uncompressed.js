/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/store/Cache",["../_base/lang","../_base/Deferred"],function(h,f){var g=function(e,d,g){return h.delegate(e,{query:function(a,b){var c=e.query(a,b);c.forEach(function(a){(!g.isLoaded||g.isLoaded(a))&&d.put(a)});return c},queryEngine:e.queryEngine||d.queryEngine,get:function(a,b){return f.when(d.get(a),function(c){return c||f.when(e.get(a,b),function(b){b&&d.put(b,{id:a});return b})})},add:function(a,b){return f.when(e.add(a,b),function(c){d.add("object"==typeof c?c:a,b);return c})},put:function(a,
b){d.remove(b&&b.id||this.getIdentity(a));return f.when(e.put(a,b),function(c){d.put("object"==typeof c?c:a,b);return c})},remove:function(a,b){return f.when(e.remove(a,b),function(){return d.remove(a,b)})},evict:function(a){return d.remove(a)}})};h.setObject("dojo.store.Cache",g);return g});