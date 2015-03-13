package com.assistanz.cloud.cloudstack.iso;

/**
 * 
 * @author Gowtham
 *
 */
public class UpdateISOPermissionResponse {
	
	/**
     * Any text associated with the success or failure on updating a ISO file
     */
    private String displayText;

   /**
    * Return true if updating ISO file operation is executed successfully
    */
   private String success;
    
   public String getDisplayText() {
        return displayText;
    }

    public void setDisplayText(String displayText) {
        this.displayText = displayText;
    }

    public String getSuccess() {
        return success;
    }

    public void setSuccess(String success) {
        this.success = success;
    }

}
