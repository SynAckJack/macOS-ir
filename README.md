# macOS-ir    [![Build Status](https://travis-ci.com/SynAckJack/macOS-ir.svg?token=whrMKztabPiqqCNsQeJt&branch=master)](https://travis-ci.com/SynAckJack/macOS-ir)

__Prototype__ tool to assist with Incident Response on macOS. Currently supports 10.15.

_Please only use the latest release if you really want to give it a shot. Currenlty in alpha. I would also recommend using the `-s` flag if you do give it a shot. This skips collecting hashes for all files and reduces the runtime a lot. Gotta flip the logic to make this default but time is short right now._

## Usage

```
usage: ./macos-ir.sh [-h | collect | analysis] [-options]

	-h    - Show this message

collect:
	-s    - Skip reading permissions of files and generating hashes.
		  Reduces overall execution time.
		    
	-u    - Copy extracted data to provided USB drive. 
		  Provided USB will be erased.

	-d    - Copy extracted data to a disk image. 
		  Disk image generated and encrypted using APFS

	-n    - Transfer collected data to another device using nc. 
		  Takes IP and port in format IP Address:Port

analysis:
	-u    - Analyse data stored on an external drive. 
		  Provide only USB name.

	-d    - Analyse data stored on a disk image.
		  Provide only disk image path.

	-n    - Receive collected data from nc. 
		  Takes only listening port.

	-i    - Install analysis tools. 
		  Installs XCode Tools and a range of other tools that are
		  required for analysis (using Homebrew).

Example:
	Collect and transmit using nc to localhost port 5555:
		./macos-ir collect -n 127.0.0.1:5555
	Receive data using nc:
		./macos-ir analysis -n 5555

	Collect, skipping file hashes, and store on usb:
		./macos-ir collect -s -u myUSB
		
	Analyse data that was saved to a disk image:
		./macos-ir analysis -d ~/Path to folder/output.dmg
```

_Full Disk Access (FDA) should be granted to `Terminal.app` on the compromised device before collection is started. This is to allow for collecting some data such as Safari browser history and downloads._

## Collection

This tool will collect data from a compromised device. This data includes:

|              | Collected Data                                                         |
| ------------ | ---------------------------------------------------------------------- |
| System       |  Hostname, Software Version, Kernel Information, Uptime, Serial Number |
| Network      |  `ifconfig` Output, ARP Table |
| Disk         |  Mounted Disks and Volumes |
| Security     |  SIP Status, EFI Integrity, MRT Version, Firewall Status, XProtect Version, Pending Updates, FileVault Status, Firmware Password Status |
| Application  |  Installed Applications, Signing Status, Install History, Running Processes, Hash of Executables |
| User         |  List of Users, Hidden Files, Login History, Sudo Users |
| File         |  File Permissions, File Paths, Created Modified Accessed Dates Per File |
| Launch       |  Cron Jobs, System and User Launch Agents and Daemons |
| Browser      |  History and Downloads for Safari, Firefox and Chrome |


To collect the data, there is no requirement for any tools to be installed. If Xcode CLI Tools are installed, then `stapler` can be used to check notarization. If these tools aren't installed, it's all good, it just won't do that which isn't the end of the world.

## Extraction

Data can be saved in one of the following methods:

*  Save to local disk image (`-d`)
*  Save to USB drive (`-u`)
*  Transfer over the network using netcat (`-n`)

_It should be noted that when transferring over the network, the other device should execute the script with `analysis -n` and this will receive and handle the data_

 ## Analysis

Before analysis begins, tools need to be installed. These are installed using [Homebrew](https://brew.sh/) with the [Brewfile](Brewfile) in this repository. Xcode Tools is also installed using `xcode-select`.

The aim of the analysis is to handle all of the data and analyse it. The data is then output to PDF files using [wkhtmltopdf](https://wkhtmltopdf.org/). 

These files aren't aimed to give the answer as to what the incident is, i.e it is this malware. It is merely meant to be used as an aid to narrow it down. This is still under development, and at a later date ideally it can be used to go into further detail and attempt to specify the malware.
 
## Feedback

Feedback is certainly welcome. If you have any issues or suggestions, feel free to let me know. I kinda suck at bash and this definitely isn't as efficient as it could be (working on it), but yeah. If you have any issues then please feel free to create one, a template has been created.

## Things I Wanna Add

Check this issue [#1](../../issues/1) for a list of things I'm wanting to work on/add
