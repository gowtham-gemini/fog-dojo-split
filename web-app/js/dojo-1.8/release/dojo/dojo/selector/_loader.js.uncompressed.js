/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/selector/_loader",["../has","require"],function(b,g){var c=document.createElement("div");b.add("dom-qsa2.1",!!c.querySelectorAll);b.add("dom-qsa3",function(){try{return c.innerHTML="<p class='TEST'></p>",1==c.querySelectorAll(".TEST:empty").length}catch(a){}});var d;return{load:function(a,c,e){var f=g,a="default"==a?b("config-selectorEngine")||"css3":a,a="css2"==a||"lite"==a?"./lite":"css2.1"==a?b("dom-qsa2.1")?"./lite":"./acme":"css3"==a?b("dom-qsa3")?"./lite":"./acme":"acme"==a?"./acme":
(f=c)&&a;if("?"==a.charAt(a.length-1))var a=a.substring(0,a.length-1),h=!0;if(h&&(b("dom-compliant-qsa")||d))return e(d);f([a],function(b){"./lite"!=a&&(d=b);e(b)})}}});