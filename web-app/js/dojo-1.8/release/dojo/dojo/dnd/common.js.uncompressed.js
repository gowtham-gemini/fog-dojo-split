/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dnd/common",["../_base/connect","../_base/kernel","../_base/lang","../dom"],function(d,e,c,f){var b={};b.getCopyKeyState=d.isCopyKey;b._uniqueId=0;b.getUniqueId=function(){var a;do a=e._scopeName+"Unique"+ ++b._uniqueId;while(f.byId(a));return a};b._empty={};b.isFormElement=function(a){a=a.target;if(3==a.nodeType)a=a.parentNode;return 0<=" button textarea input select option ".indexOf(" "+a.tagName.toLowerCase()+" ")};c.mixin(c.getObject("dojo.dnd",!0),b);return b});