define("FogPanel/ZoneCost", [
    "dojo/_base/declare",
    "dojo/dom-class",
    "dijit/_Widget",
    "dijit/form/ValidationTextBox",
    "dijit/_Templated",
    "dojo/text!FogPanel/templates/ZoneCost.html"
], function(declare, domClass,   widget, ValidationTextBox, templated, template) {
    
      return declare("FogPanel.ZoneCost", [widget, templated], {
          templateString: template,
          zoneName: "",
         
          postCreate : function() {
              var unitCostNode = this.unitCost;
              
              this.zoneCostWidget = new ValidationTextBox({
                  name:"zoneName",
                  
                  onKeyUp: function() {
                      unitCostNode.innerHTML = (this.getValue()/720).toFixed(5);
                  }
              }, this.zoneCost);
              
              this.setupCost = new ValidationTextBox({
                   required: true    
               }, this.setupCostNode);
               this.zoneNameNode.innerHTML = this.zoneName;              
          }
                    
       });
  });





