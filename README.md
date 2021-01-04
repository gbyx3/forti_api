# forti_api
:no_entry: [DEPRECATED] Active at https://github.com/gbyx3/gray_api  

I started writing this because pre fortios 6.2 Threat Feeds can't be used in IPv4 Policys  
The purpose is to block IP's based on Alerts from Graylog  
Not super dynamic in terms of what it can handle from graylog at the moment. I'll probably fix that in the future.  


## Setup

1. ) Import the graylog extractors, or alter the code to work your setup  
```
# sed -i 's/ssh_invalid_user_ip/<YOUR FIELD>//g' forti_api.py
```
  
2. ) Create a Graylog HTTP Notification and point it to your application
```
# http://127.0.0.1:8080/forti_api/v1/redis_blocklist
```

3. ) Create the event definition,  
I only set the search query to fetch messages witch contains my extractor field  
```
Search Query: _exists_:ssh_invalid_user
```
and set the notification to that you created in the previous step  


# Disclaimer
There is a address limit of 300 within the address group.  
Should probably add handling for that and address group creation at some time.  
This is not the case (as far as I can tell) when using the Threat Feeds thing..  


# Example:
Linux server authlog -> Graylog Alert -> forti_api -> Fortigate  
