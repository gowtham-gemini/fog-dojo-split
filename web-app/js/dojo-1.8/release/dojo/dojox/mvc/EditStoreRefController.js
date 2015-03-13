//>>built
define("dojox/mvc/EditStoreRefController","dojo/_base/declare,dojo/_base/lang,dojo/when,./getPlainValue,./EditModelRefController,./StoreRefController".split(","),function(h,f,i,j,k,l){return h("dojox.mvc.EditStoreRefController",[l,k],{getPlainValueOptions:null,_removals:[],_resultsWatchHandle:null,_refSourceModelProp:"sourceModel",queryStore:function(a,b){if((this.store||{}).query){this._resultsWatchHandle&&this._resultsWatchHandle.unwatch();this._removals=[];var g=this,c=this.inherited(arguments),
d=i(c,function(a){if(!g._beingDestroyed){if(f.isArray(a))g._resultsWatchHandle=a.watchElements(function(a,b){[].push.apply(g._removals,b)});return a}});d.then&&(d=f.delegate(d));for(var e in c)isNaN(e)&&c.hasOwnProperty(e)&&f.isFunction(c[e])&&(d[e]=c[e]);return d}},getStore:function(a,b){this._resultsWatchHandle&&this._resultsWatchHandle.unwatch();return this.inherited(arguments)},commit:function(){if(this._removals){for(var a=0;a<this._removals.length;a++)this.store.remove(this.store.getIdentity(this._removals[a]));
this._removals=[]}var b=j(this.get(this._refEditModelProp),this.getPlainValueOptions);if(f.isArray(b))for(a=0;a<b.length;a++)this.store.put(b[a]);else this.store.put(b);this.inherited(arguments)},reset:function(){this.inherited(arguments);this._removals=[]},destroy:function(){this._resultsWatchHandle&&this._resultsWatchHandle.unwatch();this.inherited(arguments)}})});