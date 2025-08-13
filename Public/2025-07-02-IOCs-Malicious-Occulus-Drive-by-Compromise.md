### 2025-07-02: Malicious Occulus Drive-by Compromise

Author: Usha Sree Yannapu, Balazs Greksza

References: 
https://www.ontinue.com/resources/?resource_type[]=blog
https://thehackernews.com/2024/06/warning-new-adware-campaign-targets.html
https://www.esentire.com/blog/adsexhaust-a-newly-discovered-adware-masquerading-oculus-installer 

Notes: The id parameter stores the captured hostname.

| IOC Type | Value | Name |
| ------------- | :------------- | :------------- |
| url | https[:]//files.tooldownload.net/oculus-app/download[.]php |
| url | hxxp[:]//dr5[.]org/in.mp3 | 
| url | hxxp[:]//l77[.]org/downloading.php?dl=oculus-app&id= |
| domain | l77[.]org |
| domain | dr5[.]org |
| sha1 | df85c128528b5f61c3f7597559a5bd40ea62673d | oculus-app-24-6-32-EXE.js |
| sha1 | e47d800d94b5203d9c857156858e6ba23a7bec81 | update.bat |
| sha1 | 6a8fce7190c86d46e16fec0855ad0cfbf40ca010 | oculussetup.exe |
| sha1 | 04e2f7ba3172da9f3b0f06859ff4d650eeed0aa8 | OculusSetup.exe |
