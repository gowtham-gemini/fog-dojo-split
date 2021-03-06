require({cache:{
'url:List/templates/ListItem.html':"<div class =\"ListContainer\" data-dojo-attach-point=\"listWidget\">\n    <h1 data-dojo-attach-point =\"head_text\"></h1>\n    <p data-dojo-attach-point =\"desc_text\"></p>\n    <a href=\"#\" data-dojo-attach-point=\"startNode\" id=\"startTag\" style=\"display: none\">Start</a>\n    <a href=\"#\" data-dojo-attach-point=\"stopNode\" id=\"stopTag\" style=\"display: none\">Stop</a>\n    <a href=\"#\" data-dojo-attach-point=\"rebootNode\" id=\"rebootTag\" style=\"display: none\">Reboot</a>\n    <a href=\"#\" data-dojo-attach-point=\"deleteNode\" id=\"deleteTag\">Delete</a>\n    <a href=\"#\" data-dojo-attach-point=\"attachIsoNode\" id=\"attachIsoTag\">attachIso</a>\n    <a href=\"#\" data-dojo-attach-point = \"attachNode\" id=\"attachTag\" style=\"display: none\">Attach Disk</a>\n    <a href=\"#\" data-dojo-attach-point = \"changeServiceNode\" id=\"changeServiceTag\" style=\"display: none\">Change Service</a>\n    \n</div>\n\n\n"}});
define("List/ListItem", [
    "dojo/_base/declare",   
    "dijit/_Widget",     
    "dijit/_Templated",
    "dojo/text!List/templates/ListItem.html"
], function( declare,  widget,  templated, template) {
    
      return declare("List.ListItem", [widget, templated], {
          templateString: template,
          heading: "",
          description: "",
          additionalProperties: { heading: '', description: '', zones: []},
          postCreate : function() {
            // Using the attributes defined via dojoattachpoint
            this.head_text.innerHTML = this.heading;
            this.desc_text.innerHTML = this.description;
            this.deleteNode.onclick = this.onDeleteTagClick;
            this.attachIsoNode.onclick = this.onAttachIsoTagClick;
            this.startNode.onclick = this.onStartTagClick;
            this.stopNode.onclick = this.onStopTagClick;
            this.rebootNode.onclick = this.onRebootTagClick;
            this.attachNode.onclick = this.onAttachTagClick;
            this.changeServiceNode.onclick = this.onChangeServiceTagClick;
            
        },
        getData : function() {
             this.head_text.innerHTML = this.additionalProperties.heading;
             this.desc_text.innerHTML = this.additionalProperties.description;
        }, 
        onClick : function() {},
         
         getId: function() {
           return this.id;  
         },
         
         deleteWidget: function() {
             this.listWidget.style.display = "none";
         },
         onDeleteTagClick: function() {},
         onAttachIsoTagClick: function() {},
         deleteTag: function() {
             this.deleteNode.style.display = "none";
         },
         removeDescription: function() {
             this.desc_text.style.display = "none";
         },
         onStartTagClick: function() {
             
         },
         onStopTagClick : function() {
             
         },
         onRebootTagClick: function() {
             
         },
         onAttachTagClick: function() {
             
         },
         onChangeServiceTagClick: function() {
             
         },
         enableRunningState: function() {
             this.stopNode.style.display = "block";
             this.stopNode.style.margin = "-17px 0px 0 0px";

             this.rebootNode.style.display = "block";
             this.rebootNode.style.margin = "-17px 0px 0 90px";
         },
         enableStopState: function() {
             this.startNode.style.display = "block";
             this.stopNode.style.margin = "-17px 0px 0 0px";

        },
        enableStartState: function() {
            this.stopNode.style.display = "block";
            this.rebootNode.style.display = "none";
            this.startNode.style.display = "none";
            this.deleteNode.style.display = "none";
        },
        enableAttachNode : function() {
            this.attachNode.style.display = "block";
        },
        enableChangeService: function() {
            this.changeServiceNode.style.display = "block";
        },
        disableStates: function() {
            this.stopNode.style.display = "none";
            this.rebootNode.style.display = "none";
            this.startNode.style.display = "none";
            this.deleteNode.style.display = "none";
        }
     });
 });

            