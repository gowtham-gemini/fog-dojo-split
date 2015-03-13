/*
	Copyright (c) 2004-2012, The Dojo Foundation All Rights Reserved.
	Available via Academic Free License >= 2.1 OR the modified BSD license.
	see: http://dojotoolkit.org/license for details
*/

//>>built
define("dojo/dnd/Avatar","../_base/declare,../_base/window,../dom,../dom-attr,../dom-class,../dom-construct,../hccss,../query".split(","),function(g,o,l,i,m,a,h,n){return g("dojo.dnd.Avatar",null,{constructor:function(a){this.manager=a;this.construct()},construct:function(){var j=a.create("table",{"class":"dojoDndAvatar",style:{position:"absolute",zIndex:"1999",margin:"0px"}}),b=this.manager.source,d,k=a.create("tbody",null,j),c=a.create("tr",null,k),f=a.create("td",null,c),g=Math.min(5,this.manager.nodes.length),
e=0;h("highcontrast")&&a.create("span",{id:"a11yIcon",innerHTML:this.manager.copy?"+":"<"},f);a.create("span",{innerHTML:b.generateText?this._generateText():""},f);for(i.set(c,{"class":"dojoDndAvatarHeader",style:{opacity:0.9}});e<g;++e)b.creator?d=b._normalizedCreator(b.getItem(this.manager.nodes[e].id).data,"avatar").node:(d=this.manager.nodes[e].cloneNode(!0),"tr"==d.tagName.toLowerCase()&&(c=a.create("table"),a.create("tbody",null,c).appendChild(d),d=c)),d.id="",c=a.create("tr",null,k),f=a.create("td",
null,c),f.appendChild(d),i.set(c,{"class":"dojoDndAvatarItem",style:{opacity:(9-e)/10}});this.node=j},destroy:function(){a.destroy(this.node);this.node=!1},update:function(){m.toggle(this.node,"dojoDndAvatarCanDrop",this.manager.canDropFlag);if(h("highcontrast")){var a=l.byId("a11yIcon"),b="+";this.manager.canDropFlag&&!this.manager.copy?b="< ":!this.manager.canDropFlag&&!this.manager.copy?b="o":this.manager.canDropFlag||(b="x");a.innerHTML=b}n("tr.dojoDndAvatarHeader td span"+(h("highcontrast")?
" span":""),this.node).forEach(function(a){a.innerHTML=this.manager.source.generateText?this._generateText():""},this)},_generateText:function(){return this.manager.nodes.length.toString()}})});