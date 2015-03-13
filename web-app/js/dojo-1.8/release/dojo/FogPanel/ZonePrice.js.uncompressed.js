require({cache:{
'url:FogPanel/templates/ZonePrice.html':"<div class=\"zonePriceWidget\">\n    <div class=\"row-fluid span12\" data-dojo-attach-point=\"zonePriceList\">\n        <div class=\"span2\" data-dojo-attach-point=\"zoneNameNode\"></div>\n        <div class=\"span2\">\n           <input type=\"number\" data-dojo-attach-point=\"instanceRunningCostPerMonth\"> \n        </div>\n        <span data-dojo-attach-point = \"instanceRunningCostPerHour\" class=\"unitCost span2\"> 0.00000</span>\n        <div class=\"span2\">\n           <input type=\"number\" data-dojo-attach-point=\"instanceStopageCostPerMonth\"> \n        </div>\n        <span data-dojo-attach-point = \"instanceStopageCostPerHour\" class=\"unitCost span2\"> 0.00000</span>\n        <div class=\"span2\">\n           <input type=\"number\" data-dojo-attach-point=\"setupCost\">\n        </div>\n        <span data-dojo-attach-point =\"zoneId\" style=\"display: none\"></span>    \n        <span data-dojo-attach-point=\"tempSetupCost\" class=\"\" style=\"display: none\">0</span>   \n        <span data-dojo-attach-point=\"tempMinCost\" class=\"\" style=\"display: none\">0</span> \n    </div>\n</div>\n\n\n"}});
define("FogPanel/ZonePrice", [
    "dojo/_base/lang",
    "dojo/_base/declare",
    "dojo/dom-class",
    "dijit/form/ValidationTextBox",
    "dijit/form/NumberTextBox",
    "dijit/Editor",
    "dijit/form/Button",
    "dijit/_Widget",
    "dijit/_Templated",
    "dojo/i18n",
    "dojo/text!FogPanel/templates/ZonePrice.html",
    "dojo/i18n!dijit/nls/common",
    "dojo/i18n!./nls/translator"
], function(lang, declare, domClass,  ValidationTextBox, NumberTextBox, Editor, Button, widget, templated, i18n,template) {
    
      return declare("FogPanel.ZonePrice", [widget, templated], {
          templateString: template,
          zoneName: "",
          zoneIdNode: "",
          zoneCost: "",
          setupCost:"",
          setupCostValue : "",
          minCost:"",
          costRate:"",
          calcType : "",
          diskSize : "",
          postCreate : function() {
              
              var widget = this;
              var unitCost = this.instanceRunningCostPerHour;              
              var stopageCost = this.instanceStopageCostPerHour;
              
              var invalidMessage = this.invalidMsg;
                            
//              this.zoneNameWidget = new ValidationTextBox({
//                  name:"zoneName",
//                  regExp: '[|a-z0-9A-Z- ]{4,25}',
//                  value: this.zoneName,
//                  required: true,                  
//                  missingMessage: this.warningMessage
//              }, this.zoneNameNode);
              
              this.zoneNameNode.innerHTML = this.zoneName;
              
              this.zoneId.innerHTML = this.zoneIdNode;
              
              this.zoneCostWidget = new NumberTextBox({
                  required: true,                  
                  missingMessage: invalidMessage,
                  constraints: {pattern: "#.##"},
                  invalidMessage:invalidMessage,
                  onKeyUp: function() {                    
                      if(widget.calcType == "") {
                          unitCost.innerHTML = "" + (this.getValue()/720).toFixed(5);
                          if((this.getValue()/720).toFixed(5) == "NaN") {
                              unitCost.innerHTML = " 0.00000";
                          }
                      } else if(widget.calcType == "sizeBase") {                          
                          if((this.getValue()/720).toFixed(5) == "NaN") {
                              unitCost.innerHTML = " 0.00000";
                          } else {                               
                              var resultData = (this.getValue()/widget.diskSize) / 720;
                              unitCost.innerHTML = "" + (resultData).toFixed(5);                                
                          }
                      }                    
                  },
                  onChange: function() { 
                      if(widget.calcType == "") { 
                          unitCost.innerHTML = "" + (this.getValue()/720).toFixed(5);                     
                          if((this.getValue()/720).toFixed(5) == "NaN") {
                              unitCost.innerHTML = " 0.00000";
                          }
                      } else if(widget.calcType == "sizeBase") {
                          if((this.getValue()/720).toFixed(5) == "NaN") {
                              unitCost.innerHTML = " 0.00000";
                          } else {
                              var resultData = (this.getValue()/widget.diskSize) / 720;
                              unitCost.innerHTML = "" + (resultData).toFixed(5); 
                          }                                                        
                      }                    
                  }
              }, this.instanceRunningCostPerMonth);
              
              this.minCostWidget = new NumberTextBox({
                required: true,
                constraints: {pattern: "#.##"}, 
                onKeyUp: function() {                      
                      stopageCost.innerHTML = "" + (this.getValue()/720).toFixed(5);
                      if((this.getValue()/720).toFixed(5) == "NaN") {
                          stopageCost.innerHTML = " 0.00000";
                      }
//                      alert(this.getValue())
                  },
                  onChange: function() {                     
                     stopageCost.innerHTML = "" + (this.getValue()/720).toFixed(5);                     
                     if((this.getValue()/720).toFixed(5) == "NaN") {
                          stopageCost.innerHTML = " 0.00000";
                     }
                  }
              }, this.instanceStopageCostPerMonth);
              
              this.setupCostWidget = new NumberTextBox({
                  required: true,
                  constraints: {pattern: "#.##"},
                  onChange: function() {
                  }
              }, this.setupCost);
          },
          
          setCalcType : function (currentCalcType) {
              this.calcType = currentCalcType;
          },
          
          getZoneCost : function() {
              return (this.zoneCostWidget.getValue()/720).toFixed(5);
          },          
          getZoneCostValue: function() {
              return this.zoneCostWidget.getValue();
          },
          getSetupCost: function() {
               return this.setupCostWidget.getValue().toString();
          },
          getMinCost: function() {
              return (this.minCostWidget.getValue()/720).toFixed(5);
          },
          getZoneId: function() {
              return this.zoneId.innerHTML;
          },
          setZoneId : function(zoneId) {
              this.zoneId.innerHTML = zoneId;
          },
          onClick : function() {},
          clearWidgets: function() {
              this.zoneCostWidget.reset();
              this.setupCostWidget.reset();
              this.minCostWidget.reset();
              this.instanceRunningCostPerHour.innerHTML = " 0.00000";
              this.instanceStopageCostPerHour.innerHTML = " 0.00000";              
          },
          setCost: function() {         
              this.zoneCostWidget.setValue(this.zoneCost);
          },
          setZoneCostValue : function (currentVal) {
              this.zoneCostWidget.setValue(currentVal);
          },
          setMinCost: function() {
              this.tempMinCost.innerHTML = this.minCost;
              this.minCostWidget.setValue(this.tempMinCost.innerHTML);
          },
          
          setSetupCost: function() {
              this.tempSetupCost.innerHTML = this.setupCostValue;
              this.setupCostWidget.setValue(this.tempSetupCost.innerHTML);
          },
          showErrorMsg: function() {
              var widgets = dijit.registry.findWidgets(this.zonePriceList);
              var firstNode = "";
              var status = true;
              dojo.forEach(widgets, function(el) {
                  if (el.validate && !el.validate()) {
                      el.focus();
                      status =  false;
                if (!firstNode) {
                    firstNode = el;
                }
            }
            });        
              return status;
          },
          showError: function() {
              var status = true;
              var firstNode;
              if (this.zoneCostWidget.validate && !this.zoneCostWidget.validate()) {
                      this.zoneCostWidget.focus();
                      status =  false;                    
                if (!firstNode) {
                    firstNode = this.zoneCostWidget;
                }
            }
             return status; 
             
          }          
      });
  });


