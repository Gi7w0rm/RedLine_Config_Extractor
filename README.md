# RedLine_Config_Extractor
So basically I f*cked up my main analysis VM. Therefor I am now backing this up here.

The Script works but is not usable out of the Box. I used it to extract several hundred Configs over the course of several weeks, so it was changed, reconfigured, recoded based on current needs. 

It works using unpac.me do do the heavy lifting of unpacking samples, which comes with the drawback that x64 samples are currently not supported.
Also get's Redline samples from Malware Bazaar based on yara rule. 
Extracted Info can be added to a .csv file with headers:

header = ['SHA265', 'C2_Proxy', 'Campaign_ID', 'Enc_Key']

I am still unsure if RedLine actually has C2_Proxys or if the C2 is actually always the url extracted, so if you know more, feel free to change the Naming scheme accordingly.

If you need anything, feel free to ping me on Twitter: https://twitter.com/gi7w0rm

Keep in mind, I wanted to clean this up way more, but as the machine is broken and I am focused on other things, I will leave it as is.

Huge shoutout to:
- https://twitter.com/unpacme for support regarding the API
- https://twitter.com/herrcore
- https://twitter.com/abuse_ch for literal tons of RedLine samples
- https://twitter.com/huettenhain for explaining me how I could extract configs based on byte patterns and his awesome library: https://github.com/binref/refinery

Love you guys :) 

Ps: Results of my extraction efforts can be found here:
https://github.com/Gi7w0rm/MalwareConfigLists/blob/main/RedLine/RedLine_configs.csv
