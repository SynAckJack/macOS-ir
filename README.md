# Feasibility-Demo

	- Annotated Bibliography
	- Risk Analysis

## Scripts

### systeminfo.sh
 Purpose of this script is to collect information about the target device. Currently supports collecting the following:
 
	- macOS Version
 	- Available updates
 	- EFI Integrity check
 	- XProtect last update date
 	- MRT version
 	- Install history
 	- SIP status
 
 _TO DO:_
 
 	- Output logs to file
 	- Fix ping statement to make more reliable (74706abd09402c4c51723a09462c8dcd047af794)
 	- FileVault
 	- Firewall
 	- Firmware Password


### applications.sh
Collects information regarding the currently installed Applications. Collects the following:
	
	- List of installed applications
	- Applications paths
	- Signing status of applications
	
 _TO DO:_
 	
	- Check notarization status of signed applications

 
