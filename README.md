# Threat Hunt Report (Compromised Admin Account)
**Malicious activity was detected from a compromised admin account**

## Example Scenario:
One of the administrators from the IT team calls you, the cybersecurity analyst, and tells you he is seeing some file that he has never seen before and one that he did not download; most likely due to a script. After looking into the situation more, you realize that the administrator’s account had been logged into after work hours. The goal is to analyze the events leading up to the account breach and to figure out how the file appeared on the desktop.

---

## IoC Discovery Plan:
1. Check DeviceLogonEvents for any signs of brute force attempts
2. Check DeviceFileEvents for any signs file installations and/or file deletions
3. Check DeviceProcessEvents for any signs powershell usage

---
## Steps Taken by Bad Actor
1. Attempt to brute force the password in RDP with incorrect credentials
2. Successfully log in
3. Execute Malicious Powershell script: 
```
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8AIAB3AG8AcgBsAGQ=

# Define the URL and the destination path
$url = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse2.mm.bing.net%2Fth%2Fid%2FOIP.D_2umvMRIihretglyFNrlwHaEK%3Fr%3D0%26pid%3DApi&f=1&ipt=c3186ebe04803f74c7321aa6f7a1ddc64ab70f005e924506bd045c0c41df2737&ipo=images"
$output = "C:\Users\thanos\Downloads\image.jpg"

# Download the image
Invoke-WebRequest -Uri $url -OutFile $output
```
5. Delete powershell script 
Note: Of course these actions are harmless for the purpose of the lab. The "malicious powershell script" prints "hello world" to the screen and the downloads an image of a tree.

---

## Steps Taken

1. First look for logon failures using the following query (I narrowed down the results by entering in the DeviceName):
```kql
DeviceLogonEvents
| where DeviceName == "rojas-admin"
| where ActionType == "LogonFailed"
```
The following events results were displayed:
<img width="1402" height="289" alt="image" src="https://github.com/user-attachments/assets/ce9cee7f-8b95-40a6-9949-a29bf8ec68ec" />
Due to the number of failed logon attempts (7) in a period of three seconds, I concluded that this was a brute force attempt.

2. Next, I wanted to verify if the malicious user was able to successfully logon so I slightly changed the query to search for logon successes:
```kql
DeviceLogonEvents
| where DeviceName == "rojas-admin"
| where ActionType == "LogonSuccess"
```
The following results were displayed:
<img width="1388" height="128" alt="image" src="https://github.com/user-attachments/assets/5bcd5d15-d258-49e1-a1ee-5258aad816a1" />
From this I was able to see that the connection was done remotely and from a computer named "desktop-ni4tdje" which is my host computer. This concludes that the user was able to gain access to the admin account. _Note: Although there are more logon successes, these are from me logging in minutes before starting the lab._

4. Now that the user successfully logged in, I wanted to see what they did. From what the administrator told me, the user downloaded a file named "image.jpg" so I looked for this file and how it got there using the following query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-admin"
| where ActionType == "FileCreated"
| where FileName contains "image"
```
The following results were displayed:
<img width="1405" height="256" alt="image" src="https://github.com/user-attachments/assets/c8ec9aed-8c05-4fc1-b995-6bb21cca29f6" />
The ".Ink" extension indicates powershell activity so I looked for that next.

5. Although the administor claimed he saw no scripts on the system, I decided to check you powershell events using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-admin"
| where ActionType == "ProcessCreated"
| where InitiatingProcessCommandLine contains "powershell"
```
The following events were displayed:
<img width="1408" height="289" alt="image" src="https://github.com/user-attachments/assets/9b293d53-4534-43f7-8b27-aad2cc3c4ec7" />
Since I was looking specifically for powershell events, I click on the powershell event:
</br><img width="314" height="500" alt="image" src="https://github.com/user-attachments/assets/61b41644-a787-45ef-856c-6eb1c308f41c" />
</br>This event tells me that the user used Powershell ISE to run the this command: 
</br>```"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8AIAB3AG8AcgBsAGQ=```
</br>Based on the last character of the string "=", this is a base64 encoded message that is displayed to the screen when the command runs. The following command prints to the screen "hello world." However, I still had not found an evidence of a script, so I ran the following query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-admin"
| where FileName endswith ".ps1"
```
I found the script in the results named "IT-testing" and clicked on it:
</br><img width="1391" height="229" alt="image" src="https://github.com/user-attachments/assets/00978991-034e-4183-991e-2c5ccc0c93be" />
</br>Collectively from the data, I concluded that the image was downloaded from the powershell script and the command to print "hello world" was printed to the screen. To prevent this infected system from damaging other systems on the network, I isolated the administrator's computer, "rojas-admin". (For some odd reasons, I could not verify that the script was deleted because the logs weren't showing up.)

---

## Chronological Events

1. The user brute forced the admin password and logged in
2. The user used powershell ISE to write and run the script
3. The script downloaded an image and printed text to the screen

---

## Summary

The administrator's device was compromised via brute force, ```rojas-admin``` and a script ```IT-testing.ps1``` was run. This script downloaded an image and printed text to the screen but did not implement permanent damage. This attack, although simple, stresses the importance having strong passwords and avoiding the reuse of old passwords since they can be easily compromised.

---

## Response Taken
The administrator's device was compromised via brute force, ```rojas-admin```. The device was isolated and the administrator was notified. All malicous files were deleted and a anti-malware scan was peformed.

---

## Created By:
- **Author Name**: Jeremiah Rojas
- **Author Contact**: https://www.linkedin.com/in/jeremiah-rojas-2425532b3
- **Date**: July 12, 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July  14, 2025`  | `Jeremiah Rojas`   
