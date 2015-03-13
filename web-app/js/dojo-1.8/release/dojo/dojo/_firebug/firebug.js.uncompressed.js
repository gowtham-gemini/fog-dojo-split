/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/_firebug/firebug","../_base/kernel,require,../_base/html,../sniff,../_base/array,../_base/lang,../_base/event,../_base/unload".split(","),function(h,$,S,n){function u(a){y=a||!y;if(k)k.style.display=y?"block":"none"}function aa(a,b,c,d){(a=window.open("","_firebug","status=0,menubar=0,resizable=1,top="+b+",left="+a+",width="+c+",height="+d+",scrollbars=1,addressbar=0"))||alert("Firebug Lite could not open a pop-up window, most likely because of a blocker.\nEither enable pop-ups for this domain, or change the djConfig to popup=false.");
ba(a);b=a.document;b.write('<html style="height:100%;"><head><title>Firebug Lite</title></head>\n<body bgColor="#ccc" style="height:97%;" onresize="opener.onFirebugResize()">\n<div id="fb"></div></body></html>');b.close();return a}function ba(a){var b=new Date;b.setTime(b.getTime()+5184E6);var b=b.toUTCString(),c=a.document,d;a.innerWidth?d=function(){return{w:a.innerWidth,h:a.innerHeight}}:c.documentElement&&c.documentElement.clientWidth?d=function(){return{w:c.documentElement.clientWidth,h:c.documentElement.clientHeight}}:
c.body&&(d=function(){return{w:c.body.clientWidth,h:c.body.clientHeight}});window.onFirebugResize=function(){T(d().h);clearInterval(a._firebugWin_resize);a._firebugWin_resize=setTimeout(function(){document.cookie="_firebugPosition="+[a.screenLeft,a.screenTop,a.outerWidth||a.document.body.offsetWidth,a.outerHeight||a.document.body.offsetHeight].join()+"; expires="+b+"; path=/"},5E3)}}function ca(){j=null;q.console&&q.console.clear();i=r=s=f=k=q=null;D=[];o=[];z={}}function da(){var a=i.value;i.value=
"";v([">  ",a],"command");try{eval(a)}catch(b){}}function T(a){a=a?a-(25+i.offsetHeight+25+0.01*a)+"px":k.offsetHeight-25-i.offsetHeight+"px";f.style.top="25px";f.style.height=a;s.style.height=a;s.style.top="25px";r.style.height=a;r.style.top="25px";i.style.bottom=0;h.addOnWindowUnload(ca)}function v(a,b,c){f?U(a,b,c):D.push([a,b,c])}function ea(){var a=D;D=[];for(var b=0;b<a.length;++b)U(a[b][0],a[b][1],a[b][2])}function U(a,b,c){var d=f.scrollTop+f.offsetHeight>=f.scrollHeight,c=c||fa;c(a,b);if(d)f.scrollTop=
f.scrollHeight-f.offsetHeight}function fa(a,b){var c=f.ownerDocument.createElement("div");c.className="logRow"+(b?" logRow-"+b:"");c.innerHTML=a.join("");(o.length?o[o.length-1]:f).appendChild(c)}function ga(a,b){p(a,b);var c=f.ownerDocument.createElement("div");c.className="logGroupBox";(o.length?o[o.length-1]:f).appendChild(c);o.push(c)}function ha(){o.pop()}function p(a,b){var c=[],d=a[0],e=0;"string"!=typeof d&&(d="",e=-1);for(var w=ia(d),d=0;d<w.length;++d){var f=w[d];f&&"object"==typeof f?f.appender(a[++e],
c):t(f,c)}w=[];f=[];for(d=e+1;d<a.length;++d)if(t(" ",c),e=a[d],void 0===e||null===e)M(e,c);else if("string"==typeof e)t(e,c);else if(e instanceof Date)t(e.toString(),c);else if(9==e.nodeType)t("[ XmlDoc ]",c);else{var i="_a"+ja++;w.push(i);f.push(e);e='<a id="'+i+'" href="javascript:void(0);">'+E(e)+"</a>";c.push(e+"")}v(c,b);for(d=0;d<w.length;d++)if(c=j.getElementById(w[d]))c.obj=f[d],q.console._connects.push(h.connect(c,"onclick",function(){console.openObjectInspector();try{F(this.obj)}catch(a){this.obj=
a}s.innerHTML="<pre>"+F(this.obj)+"</pre>"}))}function ia(a){for(var b=[],c=/((^%|[^\\]%)(\d+)?(\.)([a-zA-Z]))|((^%|[^\\]%)([a-zA-Z]))/,d={s:t,d:N,i:N,f:ka},e=c.exec(a);e;e=c.exec(a)){var f=e[8]?e[8]:e[5],f=f in d?d[f]:la,h=e[3]?parseInt(e[3]):"."==e[4]?-1:0;b.push(a.substr(0,"%"==e[0][0]?e.index:e.index+1));b.push({appender:f,precision:h});a=a.substr(e.index+e[0].length)}b.push(a);return b}function l(a){return(""+a).replace(/[<>&"']/g,function(a){switch(a){case "<":return"&lt;";case ">":return"&gt;";
case "&":return"&amp;";case "'":return"&#39;";case '"':return"&quot;"}return"?"})}function t(a,b){b.push(l(a+""))}function M(a,b){b.push('<span class="objectBox-null">',l(a+""),"</span>")}function N(a,b){b.push('<span class="objectBox-number">',l(a+""),"</span>")}function ka(a,b){b.push('<span class="objectBox-number">',l(a+""),"</span>")}function la(a,b){try{if(void 0===a)M("undefined",b);else if(null===a)M("null",b);else if("string"==typeof a)b.push('<span class="objectBox-string">&quot;',l(a+""),
"&quot;</span>");else if("number"==typeof a)N(a,b);else if("function"==typeof a)b.push('<span class="objectBox-function">',E(a),"</span>");else if(1==a.nodeType)b.push('<span class="objectBox-selector">'),b.push('<span class="selectorTag">',l(a.nodeName.toLowerCase()),"</span>"),a.id&&b.push('<span class="selectorId">#',l(a.id),"</span>"),a.className&&b.push('<span class="selectorClass">.',l(a.className),"</span>"),b.push("</span>");else if("object"==typeof a){var c=a+"",d=/\[object (.*?)\]/.exec(c);
b.push('<span class="objectBox-object">',d?d[1]:c,"</span>")}else t(a,b)}catch(e){}}function G(a,b){if(1==a.nodeType){b.push('<div class="objectBox-element">','&lt;<span class="nodeTag">',a.nodeName.toLowerCase(),"</span>");for(var c=0;c<a.attributes.length;++c){var d=a.attributes[c];d.specified&&b.push('&nbsp;<span class="nodeName">',d.nodeName.toLowerCase(),'</span>=&quot;<span class="nodeValue">',l(d.nodeValue),"</span>&quot;")}if(a.firstChild){b.push('&gt;</div><div class="nodeChildren">');for(c=
a.firstChild;c;c=c.nextSibling)G(c,b);b.push('</div><div class="objectBox-element">&lt;/<span class="nodeTag">',a.nodeName.toLowerCase(),"&gt;</span></div>")}else b.push("/&gt;</div>")}else 3==a.nodeType&&b.push('<div class="nodeText">',l(a.nodeValue),"</div>")}function O(a,b,c){document.all?a.attachEvent("on"+b,c):a.addEventListener(b,c,!1)}function H(a){var b=(new Date).getTime();if(b>V+200){var a=h.fixEvent(a),c=h.keys,d=a.keyCode;V=b;if(d==c.F12)u();else if((d==c.NUMPAD_ENTER||76==d)&&a.shiftKey&&
(a.metaKey||a.ctrlKey))u(!0),i&&i.focus();else return;document.all?a.cancelBubble=!0:a.stopPropagation()}}function ma(a){var b=h.keys;if(13==a.keyCode&&i.value){var a=i.value,b=(b=A("firebug_history"))?h.fromJson(b):[],c=h.indexOf(b,a);-1!=c&&b.splice(c,1);b.push(a);for(A("firebug_history",h.toJson(b),30);b.length&&!A("firebug_history");)b.shift(),A("firebug_history",h.toJson(b),30);B=null;m=-1;da()}else if(27==a.keyCode)i.value="";else if(a.keyCode==b.UP_ARROW||a.charCode==b.UP_ARROW)I("older");
else if(a.keyCode==b.DOWN_ARROW||a.charCode==b.DOWN_ARROW)I("newer");else if(a.keyCode==b.HOME||a.charCode==b.HOME)m=1,I("older");else if(a.keyCode==b.END||a.charCode==b.END)m=999999,I("newer")}function I(a){var b=A("firebug_history"),b=b?h.fromJson(b):[];if(b.length){if(null===B)B=i.value;if(-1==m)m=b.length;if("older"==a)--m,0>m&&(m=0);else if("newer"==a&&(++m,m>b.length))m=b.length;m==b.length?(i.value=B,B=null):i.value=b[m]}}function A(a,b){var c=document.cookie;if(1==arguments.length)return(c=
c.match(RegExp("(?:^|; )"+a+"=([^;]*)")))?decodeURIComponent(c[1]):void 0;c=new Date;c.setMonth(c.getMonth()+1);document.cookie=a+"="+encodeURIComponent(b)+(c.toUtcString?"; expires="+c.toUTCString():"")}function W(a){return a&&a instanceof Array||"array"==typeof a}function F(a,b,c,d){var c=c||"",b=b||" \t",d=d||[],e;if(a&&1==a.nodeType)return b=[],G(a,b),b.join("");var f=",\n",h=0,i;i=0;for(e in a)i++;if(a instanceof Date)return b+a.toString()+f;var g;a:for(g in a)if(h++,h==i&&(f="\n"),!(a[g]===
window||a[g]===document))if(null===a[g])c+=b+g+" : NULL"+f;else if(a[g]&&a[g].nodeType)1!=a[g].nodeType&&3==a[g].nodeType&&(c+=b+g+" : [ TextNode "+a[g].data+" ]"+f);else if("object"==typeof a[g]&&(a[g]instanceof String||a[g]instanceof Number||a[g]instanceof Boolean))c+=b+g+" : "+a[g]+","+f;else if(a[g]instanceof Date)c+=b+g+" : "+a[g].toString()+f;else if("object"==typeof a[g]&&a[g]){e=0;for(var j;j=d[e];e++)if(a[g]===j){c+=b+g+" : RECURSION"+f;continue a}d.push(a[g]);e=W(a[g])?["[","]"]:["{","}"];
c+=b+g+" : "+e[0]+"\n";c+=F(a[g],b+" \t","",d);c+=b+e[1]+f}else"undefined"==typeof a[g]?c+=b+g+" : undefined"+f:"toString"==g&&"function"==typeof a[g]?(e=a[g](),"string"==typeof e&&e.match(/function ?(.*?)\(/)&&(e=l(E(a[g]))),c+=b+g+" : "+e+f):c+=b+g+" : "+l(E(a[g]))+f;return c}function E(a){var b=a instanceof Error;if(1==a.nodeType)return l("< "+a.tagName.toLowerCase()+' id="'+a.id+'" />');if(3==a.nodeType)return l('[TextNode: "'+a.nodeValue+'"]');var c=a&&(a.id||a.name||a.ObjectID||a.widgetId);
if(!b&&c)return"{"+c+"}";var d=0;if(b)c="[ Error: "+(a.message||a.description||a)+" ]";else if(W(a))c="["+a.slice(0,4).join(","),4<a.length&&(c+=" ... ("+a.length+" items)"),c+="]";else if("function"==typeof a)(a=/function\s*([^\(]*)(\([^\)]*\))[^\{]*\{/.exec(a+""))?(a[1]||(a[1]="function"),c=a[1]+a[2]):c="function()";else if("object"!=typeof a||"string"==typeof a)c=a+"";else{var c="{",e;for(e in a){d++;if(2<d)break;c+=e+":"+l(a[e])+"  "}c+="}"}return c}if(S=/Trident/.test(window.navigator.userAgent)){for(var P=
["log","info","debug","warn","error"],J=0;J<P.length;J++){var K=P[J];if(console[K]&&!console[K]._fake){var X="_"+P[J];console[X]=console[K];console[K]=function(){var a=X;return function(){console[a](Array.prototype.join.call(arguments," "))}}()}}try{console.clear()}catch(na){}}if(!n("ff")&&!n("chrome")&&!n("safari")&&!S&&!window.firebug&&!("undefined"!=typeof console&&console.firebug||h.config.useCustomLogger||n("air"))){try{if(window!=window.parent){if(window.parent.console)window.console=window.parent.console;
return}}catch(oa){}var j=document,q=window,ja=0,k=null,f=null,s=null,i=null,y=!1,D=[],o=[],z={},L={},r=null,Y,Q,C=!1,R=null;document.createElement("div");var x,Z;window.console={_connects:[],log:function(){p(arguments,"")},debug:function(){p(arguments,"debug")},info:function(){p(arguments,"info")},warn:function(){p(arguments,"warning")},error:function(){p(arguments,"error")},assert:function(a,b){if(!a){for(var c=[],d=1;d<arguments.length;++d)c.push(arguments[d]);p(c.length?c:["Assertion Failure"],
"error");throw b?b:"Assertion Failure";}},dir:function(a){a=F(a);a=a.replace(/\n/g,"<br />");a=a.replace(/\t/g,"&nbsp;&nbsp;&nbsp;&nbsp;");v([a],"dir")},dirxml:function(a){var b=[];G(a,b);v(b,"dirxml")},group:function(){v(arguments,"group",ga)},groupEnd:function(){v(arguments,"",ha)},time:function(a){z[a]=(new Date).getTime()},timeEnd:function(a){if(a in z){var b=(new Date).getTime()-z[a];p([a+":",b+"ms"]);delete z[a]}},count:function(a){L[a]||(L[a]=0);L[a]++;p([a+": "+L[a]])},trace:function(a){for(var a=
a||3,b=console.trace.caller,c=0;c<a;c++){for(var d=[],e=0;e<b.arguments.length;e++)d.push(b.arguments[e]);b=b.caller}},profile:function(){this.warn(["profile() not supported."])},profileEnd:function(){},clear:function(){if(f)for(;f.childNodes.length;)h.destroy(f.firstChild);h.forEach(this._connects,h.disconnect)},open:function(){u(!0)},close:function(){y&&u()},_restoreBorder:function(){if(x)x.style.border=Z},openDomInspector:function(){C=!0;f.style.display="none";r.style.display="block";s.style.display=
"none";document.body.style.cursor="pointer";Y=h.connect(document,"mousemove",function(a){if(C&&!R&&(R=setTimeout(function(){R=null},50),(a=a.target)&&x!==a)){console._restoreBorder();var b=[];G(a,b);r.innerHTML=b.join("");x=a;Z=x.style.border;x.style.border="#0000FF 1px solid"}});setTimeout(function(){Q=h.connect(document,"click",function(){document.body.style.cursor="";C=!C;h.disconnect(Q)})},30)},_closeDomInspector:function(){document.body.style.cursor="";h.disconnect(Y);h.disconnect(Q);C=!1;console._restoreBorder()},
openConsole:function(){f.style.display="block";r.style.display="none";s.style.display="none";console._closeDomInspector()},openObjectInspector:function(){f.style.display="none";r.style.display="none";s.style.display="block";console._closeDomInspector()},recss:function(){var a,b,c;b=document.getElementsByTagName("link");for(a=0;a<b.length;a++)if(c=b[a],0<=c.rel.toLowerCase().indexOf("stylesheet")&&c.href){var d=c.href.replace(/(&|%5C?)forceReload=\d+/,"");c.href=d+(0<=d.indexOf("?")?"&":"?")+"forceReload="+
(new Date).valueOf()}}};h.addOnLoad(function(){if(!k){u(!0);if(h.config.popup){var a="100%",b=document.cookie.match(/(?:^|; )_firebugPosition=([^;]*)/),b=b?b[1].split(","):[2,2,320,480];q=aa(b[0],b[1],b[2],b[3]);j=q.document;h.config.debugContainerId="fb";q.console=window.console;q.dojo=window.dojo}else j=document,a=(h.config.debugHeight||300)+"px";var c=j.createElement("link");c.href=$.toUrl("./firebug.css");c.rel="stylesheet";c.type="text/css";var d=j.getElementsByTagName("head");d&&(d=d[0]);d||
(d=j.getElementsByTagName("html")[0]);n("ie")?window.setTimeout(function(){d.appendChild(c)},0):d.appendChild(c);h.config.debugContainerId&&(k=j.getElementById(h.config.debugContainerId));k||(k=j.createElement("div"),j.body.appendChild(k));k.className+=" firebug";k.id="firebug";k.style.height=a;k.style.display=y?"block":"none";a=function(a,b,c,d){return'<li class="'+d+'"><a href="javascript:void(0);" onclick="console.'+c+'(); return false;" title="'+b+'">'+a+"</a></li>"};k.innerHTML='<div id="firebugToolbar">  <ul id="fireBugTabs" class="tabs">'+
a("Clear","Remove All Console Logs","clear","")+a("ReCSS","Refresh CSS without reloading page","recss","")+a("Console","Show Console Logs","openConsole","gap")+a("DOM","Show DOM Inspector","openDomInspector","")+a("Object","Show Object Inspector","openObjectInspector","")+(h.config.popup?"":a("Close","Close the console","close","gap"))+'\t</ul></div><input type="text" id="firebugCommandLine" /><div id="firebugLog"></div><div id="objectLog" style="display:none;">Click on an object in the Log display</div><div id="domInspect" style="display:none;">Hover over HTML elements in the main page. Click to hold selection.</div>';
j.getElementById("firebugToolbar");i=j.getElementById("firebugCommandLine");O(i,"keydown",ma);O(j,n("ie")||n("safari")?"keydown":"keypress",H);f=j.getElementById("firebugLog");s=j.getElementById("objectLog");r=j.getElementById("domInspect");j.getElementById("fireBugTabs");T();ea()}});var V=(new Date).getTime(),m=-1,B=null;O(document,n("ie")||n("safari")?"keydown":"keypress",H);("true"==document.documentElement.getAttribute("debug")||h.config.isDebug)&&u(!0);h.addOnWindowUnload(function(){var a=document,
b=n("ie")||n("safari")?"keydown":"keypress";document.all?a.detachEvent("on"+b,H):a.removeEventListener(b,H,!1);window.onFirebugResize=null;window.console=null})}});