//>>built
define("dojox/app/utils/simpleModel",["dojo/_base/lang","dojo/Deferred","dojo/when","dojo/_base/config","dojo/store/DataStore"],function(g,h,i,j,k){return function(j,a){var c,e,b={},d=new h;if(a.store)a.store.params.data||a.store.params.store?(c=a.store.store,e=void 0):a.store.params.url&&(c=new k({store:a.store.store}),e=void 0);else if(a.data){if(a.data&&g.isString(a.data))a.data=g.getObject(a.data);e=a.data;c=void 0}var f;try{f=c?c.query():e}catch(l){return d.reject("load mvc model error."),d.promise}if(f.then)i(f,
g.hitch(this,function(a){b=a;d.resolve(b);return b}),function(){loadModelLoaderDeferred.reject("load model error.")});else return b=f,d.resolve(b),b;return d}});