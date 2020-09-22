## forti_api
I started writing this because pre fortios 6.2 Threat Feeds can't be used in IPv4 Policys

The purpose is to block IP's based on Alerts within Graylog

Not super dynamic in terms of what it can handle from graylog at the moment. I'll probably fix that in the future.


## Disclaimer
There is a address limit of 300 within the address group. 

Should probably add handling for that and address group creation at some time.

This is not the case (as far as I can tell) when using the Threat Feeds thing..


## Example:
Linux server authlog -> Graylog Alert -> forti_api -> Fortigate







