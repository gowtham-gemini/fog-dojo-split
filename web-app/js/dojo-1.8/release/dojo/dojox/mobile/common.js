//>>built
define("dojox/mobile/common","dojo/_base/array,dojo/_base/config,dojo/_base/connect,dojo/_base/lang,dojo/_base/window,dojo/dom-class,dojo/dom-construct,dojo/ready,dijit/registry,./sniff,./uacss".split(","),function(l,f,i,j,b,k,n,o,p,c){var a=j.getObject("dojox.mobile",!0);a.getScreenSize=function(){return{h:b.global.innerHeight||b.doc.documentElement.clientHeight,w:b.global.innerWidth||b.doc.documentElement.clientWidth}};a.updateOrient=function(){var d=a.getScreenSize();k.replace(b.doc.documentElement,
d.h>d.w?"dj_portrait":"dj_landscape",d.h>d.w?"dj_landscape":"dj_portrait")};a.updateOrient();a.tabletSize=500;a.detectScreenSize=function(d){var e=a.getScreenSize(),c=Math.min(e.w,e.h),g,h;if(c>=a.tabletSize&&(d||!this._sz||this._sz<a.tabletSize))g="phone",h="tablet";else if(c<a.tabletSize&&(d||!this._sz||this._sz>=a.tabletSize))g="tablet",h="phone";h&&(k.replace(b.doc.documentElement,"dj_"+h,"dj_"+g),i.publish("/dojox/mobile/screenSize/"+h,[e]));this._sz=c};a.detectScreenSize();a.hideAddressBarWait=
"number"===typeof f.mblHideAddressBarWait?f.mblHideAddressBarWait:1500;a.hide_1=function(){scrollTo(0,1);a._hidingTimer=0==a._hidingTimer?200:2*a._hidingTimer;setTimeout(function(){a.isAddressBarHidden()||a._hidingTimer>a.hideAddressBarWait?(a.resizeAll(),a._hiding=!1):setTimeout(a.hide_1,a._hidingTimer)},50)};a.hideAddressBar=function(){if(!a.disableHideAddressBar&&!a._hiding){a._hiding=!0;a._hidingTimer=c("iphone")?200:0;var d=screen.availHeight;if(c("android")){d=outerHeight/devicePixelRatio;if(0==
d)a._hiding=!1,setTimeout(function(){a.hideAddressBar()},200);d<=innerHeight&&(d=outerHeight);if(3>c("android"))b.doc.documentElement.style.overflow=b.body().style.overflow="visible"}if(b.body().offsetHeight<d)b.body().style.minHeight=d+"px",a._resetMinHeight=!0;setTimeout(a.hide_1,a._hidingTimer)}};a.isAddressBarHidden=function(){return 1===pageYOffset};a.resizeAll=function(d,e){if(!a.disableResizeAll){i.publish("/dojox/mobile/resizeAll",[d,e]);i.publish("/dojox/mobile/beforeResizeAll",[d,e]);if(a._resetMinHeight)b.body().style.minHeight=
a.getScreenSize().h+"px";a.updateOrient();a.detectScreenSize();var c=function(a){var b=a.getParent&&a.getParent();return!(b&&b.resize||!a.resize)},g=function(a){l.forEach(a.getChildren(),function(a){c(a)&&a.resize();g(a)})};e?(e.resize&&e.resize(),g(e)):l.forEach(l.filter(p.toArray(),c),function(a){a.resize()});i.publish("/dojox/mobile/afterResizeAll",[d,e])}};a.openWindow=function(a,c){b.global.open(a,c||"_blank")};!1!==f.mblApplyPageStyles&&k.add(b.doc.documentElement,"mobile");c("chrome")&&k.add(b.doc.documentElement,
"dj_chrome");if(b.global._no_dojo_dm){var j=b.global._no_dojo_dm,m;for(m in j)a[m]=j[m];a.deviceTheme.setDm(a)}c.add("mblAndroidWorkaround",!1!==f.mblAndroidWorkaround&&3>c("android"),void 0,!0);c.add("mblAndroid3Workaround",!1!==f.mblAndroid3Workaround&&3<=c("android"),void 0,!0);o(function(){a.detectScreenSize(!0);!1!==f.mblAndroidWorkaroundButtonStyle&&c("android")&&n.create("style",{innerHTML:"BUTTON,INPUT[type='button'],INPUT[type='submit'],INPUT[type='reset'],INPUT[type='file']::-webkit-file-upload-button{-webkit-appearance:none;}"},
b.doc.head,"first");c("mblAndroidWorkaround")&&n.create("style",{innerHTML:".mblView.mblAndroidWorkaround{position:absolute;top:-9999px !important;left:-9999px !important;}"},b.doc.head,"last");var d=a.resizeAll;if(!1!==f.mblHideAddressBar&&-1!=navigator.appVersion.indexOf("Mobile")||!0===f.mblForceHideAddressBar)if(a.hideAddressBar(),!0===f.mblAlwaysHideAddressBar)d=a.hideAddressBar;var e=6<=c("iphone");if((c("android")||e)&&void 0!==b.global.onorientationchange){var j=d,g,h,k;e?(h=b.doc.documentElement.clientWidth,
k=b.doc.documentElement.clientHeight):(d=function(){var a=i.connect(null,"onresize",null,function(b){i.disconnect(a);j(b)})},g=a.getScreenSize());i.connect(null,"onresize",null,function(d){if(e){var c=b.doc.documentElement.clientWidth,f=b.doc.documentElement.clientHeight;c==h&&f!=k&&j(d);h=c;k=f}else c=a.getScreenSize(),c.w==g.w&&100<=Math.abs(c.h-g.h)&&j(d),g=c})}i.connect(null,void 0!==b.global.onorientationchange?"onorientationchange":"onresize",null,d);b.body().style.visibility="visible"});return a});