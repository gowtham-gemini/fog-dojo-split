//>>built
require({cache:{"url:dijit/templates/InlineEditBox.html":'<span data-dojo-attach-point="editNode" role="presentation" class="dijitReset dijitInline dijitOffScreen"\n\tdata-dojo-attach-event="onkeypress: _onKeyPress"\n\t><span data-dojo-attach-point="editorPlaceholder"></span\n\t><span data-dojo-attach-point="buttonContainer"\n\t\t><button data-dojo-type="dijit/form/Button" data-dojo-props="label: \'${buttonSave}\', \'class\': \'saveButton\'"\n\t\t\tdata-dojo-attach-point="saveButton" data-dojo-attach-event="onClick:save"></button\n\t\t><button data-dojo-type="dijit/form/Button"  data-dojo-props="label: \'${buttonCancel}\', \'class\': \'cancelButton\'"\n\t\t\tdata-dojo-attach-point="cancelButton" data-dojo-attach-event="onClick:cancel"></button\n\t></span\n></span>\n'}});
define("dijit/InlineEditBox","require,dojo/_base/array,dojo/_base/declare,dojo/dom-attr,dojo/dom-class,dojo/dom-construct,dojo/dom-style,dojo/_base/event,dojo/i18n,dojo/_base/kernel,dojo/keys,dojo/_base/lang,dojo/sniff,dojo/when,./focus,./_Widget,./_TemplatedMixin,./_WidgetsInTemplateMixin,./_Container,./form/Button,./form/_TextBoxMixin,./form/TextBox,dojo/text!./templates/InlineEditBox.html,dojo/i18n!./nls/common".split(","),function(r,j,f,k,d,o,h,l,s,m,p,e,t,u,n,q,i,v,z,A,w,x,y){i=f("dijit._InlineEditor",
[q,i,v],{templateString:y,postMixInProperties:function(){this.inherited(arguments);this.messages=s.getLocalization("dijit","common",this.lang);j.forEach(["buttonSave","buttonCancel"],function(a){this[a]||(this[a]=this.messages[a])},this)},buildRendering:function(){this.inherited(arguments);var a="string"==typeof this.editor?e.getObject(this.editor)||r(this.editor):this.editor,b=this.sourceStyle,c="line-height:"+b.lineHeight+";",d=h.getComputedStyle(this.domNode);j.forEach(["Weight","Family","Size",
"Style"],function(a){d["font"+a]!=b["font"+a]&&(c+="font-"+a+":"+b["font"+a]+";")},this);j.forEach("marginTop,marginBottom,marginLeft,marginRight,position,left,top,right,bottom,float,clear,display".split(","),function(a){this.domNode.style[a]=b[a]},this);var g=this.inlineEditBox.width;"100%"==g?(c+="width:100%;",this.domNode.style.display="block"):c+="width:"+(g+(Number(g)==g?"px":""))+";";g=e.delegate(this.inlineEditBox.editorParams,{style:c,dir:this.dir,lang:this.lang,textDir:this.textDir});this.editWidget=
new a(g,this.editorPlaceholder);this.inlineEditBox.autoSave&&o.destroy(this.buttonContainer)},postCreate:function(){this.inherited(arguments);var a=this.editWidget;this.inlineEditBox.autoSave?(this.connect(a,"onChange","_onChange"),this.connect(a,"onKeyPress","_onKeyPress")):"intermediateChanges"in a&&(a.set("intermediateChanges",!0),this.connect(a,"onChange","_onIntermediateChange"),this.saveButton.set("disabled",!0))},startup:function(){this.editWidget.startup();this.inherited(arguments)},_onIntermediateChange:function(){this.saveButton.set("disabled",
this.getValue()==this._resetValue||!this.enableSave())},destroy:function(){this.editWidget.destroy(!0);this.inherited(arguments)},getValue:function(){var a=this.editWidget;return""+a.get("displayedValue"in a||"_getDisplayedValueAttr"in a?"displayedValue":"value")},_onKeyPress:function(a){this.inlineEditBox.autoSave&&this.inlineEditBox.editing&&!a.altKey&&!a.ctrlKey&&(a.charOrCode==p.ESCAPE?(l.stop(a),this.cancel(!0)):a.charOrCode==p.ENTER&&"INPUT"==a.target.tagName&&(l.stop(a),this._onChange()))},
_onBlur:function(){this.inherited(arguments);this.inlineEditBox.autoSave&&this.inlineEditBox.editing&&(this.getValue()==this._resetValue?this.cancel(!1):this.enableSave()&&this.save(!1))},_onChange:function(){this.inlineEditBox.autoSave&&this.inlineEditBox.editing&&this.enableSave()&&n.focus(this.inlineEditBox.displayNode)},enableSave:function(){return this.editWidget.isValid?this.editWidget.isValid():!0},focus:function(){this.editWidget.focus();this.editWidget.focusNode&&(n._onFocusNode(this.editWidget.focusNode),
"INPUT"==this.editWidget.focusNode.tagName&&this.defer(function(){w.selectInputText(this.editWidget.focusNode)}))}});f=f("dijit.InlineEditBox",q,{editing:!1,autoSave:!0,buttonSave:"",buttonCancel:"",renderAsHtml:!1,editor:x,editorWrapper:i,editorParams:{},disabled:!1,onChange:function(){},onCancel:function(){},width:"100%",value:"",noValueIndicator:6>=t("ie")?"<span style='font-family: wingdings; text-decoration: underline;'>&#160;&#160;&#160;&#160;&#x270d;&#160;&#160;&#160;&#160;</span>":"<span style='text-decoration: underline;'>&#160;&#160;&#160;&#160;&#x270d;&#160;&#160;&#160;&#160;</span>",
constructor:function(){this.editorParams={}},postMixInProperties:function(){this.inherited(arguments);this.displayNode=this.srcNodeRef;var a={ondijitclick:"_onClick",onmouseover:"_onMouseOver",onmouseout:"_onMouseOut",onfocus:"_onMouseOver",onblur:"_onMouseOut"},b;for(b in a)this.connect(this.displayNode,b,a[b]);this.displayNode.setAttribute("role","button");this.displayNode.getAttribute("tabIndex")||this.displayNode.setAttribute("tabIndex",0);if(!this.value&&!("value"in this.params))this.value=e.trim(this.renderAsHtml?
this.displayNode.innerHTML:this.displayNode.innerText||this.displayNode.textContent||"");if(!this.value)this.displayNode.innerHTML=this.noValueIndicator;d.add(this.displayNode,"dijitInlineEditBoxDisplayMode")},setDisabled:function(a){m.deprecated("dijit.InlineEditBox.setDisabled() is deprecated.  Use set('disabled', bool) instead.","","2.0");this.set("disabled",a)},_setDisabledAttr:function(a){this.domNode.setAttribute("aria-disabled",a?"true":"false");a?this.displayNode.removeAttribute("tabIndex"):
this.displayNode.setAttribute("tabIndex",0);d.toggle(this.displayNode,"dijitInlineEditBoxDisplayModeDisabled",a);this._set("disabled",a)},_onMouseOver:function(){this.disabled||d.add(this.displayNode,"dijitInlineEditBoxDisplayModeHover")},_onMouseOut:function(){d.remove(this.displayNode,"dijitInlineEditBoxDisplayModeHover")},_onClick:function(a){this.disabled||(a&&l.stop(a),this._onMouseOut(),this.defer("edit"))},edit:function(){if(!this.disabled&&!this.editing){this._set("editing",!0);this._savedTabIndex=
k.get(this.displayNode,"tabIndex")||"0";if(!this.wrapperWidget){var a=o.create("span",null,this.domNode,"before");this.wrapperWidget=new ("string"==typeof this.editorWrapper?e.getObject(this.editorWrapper):this.editorWrapper)({value:this.value,buttonSave:this.buttonSave,buttonCancel:this.buttonCancel,dir:this.dir,lang:this.lang,tabIndex:this._savedTabIndex,editor:this.editor,inlineEditBox:this,sourceStyle:h.getComputedStyle(this.displayNode),save:e.hitch(this,"save"),cancel:e.hitch(this,"cancel"),
textDir:this.textDir},a);this.wrapperWidget._started||this.wrapperWidget.startup();this._started||this.startup()}var b=this.wrapperWidget;d.add(this.displayNode,"dijitOffScreen");d.remove(b.domNode,"dijitOffScreen");h.set(b.domNode,{visibility:"visible"});k.set(this.displayNode,"tabIndex","-1");var c=b.editWidget,f=this;u(c.onLoadDeferred,e.hitch(b,function(){c.set("displayedValue"in c||"_setDisplayedValueAttr"in c?"displayedValue":"value",f.value);this.defer(function(){b.saveButton.set("disabled",
"intermediateChanges"in c);this.focus();this._resetValue=this.getValue()})}))}},_onBlur:function(){this.inherited(arguments)},destroy:function(){this.wrapperWidget&&!this.wrapperWidget._destroyed&&(this.wrapperWidget.destroy(),delete this.wrapperWidget);this.inherited(arguments)},_showText:function(a){var b=this.wrapperWidget;h.set(b.domNode,{visibility:"hidden"});d.add(b.domNode,"dijitOffScreen");d.remove(this.displayNode,"dijitOffScreen");k.set(this.displayNode,"tabIndex",this._savedTabIndex);a&&
n.focus(this.displayNode)},save:function(a){!this.disabled&&this.editing&&(this._set("editing",!1),this.set("value",this.wrapperWidget.getValue()),this._showText(a))},setValue:function(a){m.deprecated("dijit.InlineEditBox.setValue() is deprecated.  Use set('value', ...) instead.","","2.0");return this.set("value",a)},_setValueAttr:function(a){a=e.trim(a);this.displayNode.innerHTML=(this.renderAsHtml?a:a.replace(/&/gm,"&amp;").replace(/</gm,"&lt;").replace(/>/gm,"&gt;").replace(/"/gm,"&quot;").replace(/\n/g,
"<br>"))||this.noValueIndicator;this._set("value",a);this._started&&this.defer(function(){this.onChange(a)});"auto"==this.textDir&&this.applyTextDir(this.displayNode,this.displayNode.innerText)},getValue:function(){m.deprecated("dijit.InlineEditBox.getValue() is deprecated.  Use get('value') instead.","","2.0");return this.get("value")},cancel:function(a){!this.disabled&&this.editing&&(this._set("editing",!1),this.defer("onCancel"),this._showText(a))},_setTextDirAttr:function(a){if(!this._created||
this.textDir!=a)this._set("textDir",a),this.applyTextDir(this.displayNode,this.displayNode.innerText),this.displayNode.align="rtl"==this.dir?"right":"left"}});f._InlineEditor=i;return f});