/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/on",["./has!dom-addeventlistener?:./aspect","./_base/kernel","./has"],function(s,t,h){function u(a,c,b,d,f){if(d=c.match(/(.*):(.*)/))return c=d[2],d=d[1],i.selector(d,c).call(f,a,b);h("touch")&&(v.test(c)&&(b=l(b)),!h("event-orientationchange")&&"orientationchange"==c&&(c="resize",a=window,b=l(b)));m&&(b=m(b));if(a.addEventListener){var g=c in k,e=g?k[c]:c;a.addEventListener(e,b,g);return{remove:function(){a.removeEventListener(e,b,g)}}}if(n&&a.attachEvent)return n(a,"on"+c,b);throw Error("Target must be an event emitter");
}function w(){this.cancelable=!1}function x(){this.bubbles=!1}var o=window.ScriptEngineMajorVersion;h.add("jscript",o&&o()+ScriptEngineMinorVersion()/10);h.add("event-orientationchange",h("touch")&&!h("android"));h.add("event-stopimmediatepropagation",window.Event&&!!window.Event.prototype&&!!window.Event.prototype.stopImmediatePropagation);var i=function(a,c,b,d){return"function"==typeof a.on&&"function"!=typeof c&&!a.nodeType?a.on(c,b):i.parse(a,c,b,u,d,this)};i.pausable=function(a,c,b,d){var f,
a=i(a,c,function(){if(!f)return b.apply(this,arguments)},d);a.pause=function(){f=!0};a.resume=function(){f=!1};return a};i.once=function(a,c,b){var d=i(a,c,function(){d.remove();return b.apply(this,arguments)});return d};i.parse=function(a,c,b,d,f,g){if(c.call)return c.call(g,a,b);if(-1<c.indexOf(",")){for(var c=c.split(/\s*,\s*/),e=[],i=0,h;h=c[i++];)e.push(d(a,h,b,f,g));e.remove=function(){for(var a=0;a<e.length;a++)e[a].remove()};return e}return d(a,c,b,f,g)};var v=/^touch/;i.selector=function(a,
c,b){return function(d,f){function g(c){for(e=e&&e.matches?e:t.query;!e.matches(c,a,d);)if(c==d||!1===b||!(c=c.parentNode)||1!=c.nodeType)return;return c}var e="function"==typeof a?{matches:a}:this,h=c.bubble;return h?i(d,h(g),f):i(d,c,function(a){var b=g(a.target);return b&&f.call(b,a)})}};var y=[].slice,z=i.emit=function(a,c,b){var d=y.call(arguments,2),f="on"+c;if("parentNode"in a){var g=d[0]={},e;for(e in b)g[e]=b[e];g.preventDefault=w;g.stopPropagation=x;g.target=a;g.type=c;b=g}do a[f]&&a[f].apply(a,
d);while(b&&b.bubbles&&(a=a.parentNode));return b&&b.cancelable&&b},k={};if(!h("event-stopimmediatepropagation"))var A=function(){this.modified=this.immediatelyStopped=!0},m=function(a){return function(c){if(!c.immediatelyStopped)return c.stopImmediatePropagation=A,a.apply(this,arguments)}};if(h("dom-addeventlistener"))k={focusin:"focus",focusout:"blur"},i.emit=function(a,c,b){if(a.dispatchEvent&&document.createEvent){var d=a.ownerDocument.createEvent("HTMLEvents");d.initEvent(c,!!b.bubbles,!!b.cancelable);
for(var f in b)f in d||(d[f]=b[f]);return a.dispatchEvent(d)&&d}return z.apply(i,arguments)};else{i._fixEvent=function(a,c){if(!a)a=(c&&(c.ownerDocument||c.document||c).parentWindow||window).event;if(!a)return a;j&&a.type==j.type&&(a=j);if(!a.target){a.target=a.srcElement;a.currentTarget=c||a.srcElement;if("mouseover"==a.type)a.relatedTarget=a.fromElement;if("mouseout"==a.type)a.relatedTarget=a.toElement;if(!a.stopPropagation)a.stopPropagation=B,a.preventDefault=C;switch(a.type){case "keypress":var b=
"charCode"in a?a.charCode:a.keyCode;10==b?(b=0,a.keyCode=13):13==b||27==b?b=0:3==b&&(b=99);a.charCode=b;b=a;b.keyChar=b.charCode?String.fromCharCode(b.charCode):"";b.charOrCode=b.keyChar||b.keyCode}}return a};var j,p=function(a){this.handle=a};p.prototype.remove=function(){delete _dojoIEListeners_[this.handle]};var D=function(a){return function(c){var c=i._fixEvent(c,this),b=a.call(this,c);c.modified&&(j||setTimeout(function(){j=null}),j=c);return b}},n=function(a,c,b){b=D(b);if(((a.ownerDocument?
a.ownerDocument.parentWindow:a.parentWindow||a.window||window)!=top||5.8>h("jscript"))&&!h("config-_allow_leaks")){"undefined"==typeof _dojoIEListeners_&&(_dojoIEListeners_=[]);var d=a[c];if(!d||!d.listeners){var f=d,d=Function("event","var callee = arguments.callee; for(var i = 0; i<callee.listeners.length; i++){var listener = _dojoIEListeners_[callee.listeners[i]]; if(listener){listener.call(this,event);}}");d.listeners=[];a[c]=d;d.global=this;f&&d.listeners.push(_dojoIEListeners_.push(f)-1)}d.listeners.push(a=
d.global._dojoIEListeners_.push(b)-1);return new p(a)}return s.after(a,c,b,!0)},B=function(){this.cancelBubble=!0},C=i._preventDefault=function(){this.bubbledKeyCode=this.keyCode;if(this.ctrlKey)try{this.keyCode=0}catch(a){}this.defaultPrevented=!0;this.returnValue=!1}}if(h("touch"))var q=function(){},r=window.orientation,l=function(a){return function(c){var b=c.corrected;if(!b){var d=c.type;try{delete c.type}catch(f){}if(c.type){if(h("mozilla")){var b={},g;for(g in c)b[g]=c[g]}else q.prototype=c,
b=new q;b.preventDefault=function(){c.preventDefault()};b.stopPropagation=function(){c.stopPropagation()}}else b=c,b.type=d;c.corrected=b;if("resize"==d){if(r==window.orientation)return null;r=window.orientation;b.type="orientationchange";return a.call(this,b)}if(!("rotation"in b))b.rotation=0,b.scale=1;var d=b.changedTouches[0],e;for(e in d)delete b[e],b[e]=d[e]}return a.call(this,b)}};return i});