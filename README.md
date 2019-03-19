# Mockfb

This projects Mocks the functionality of facebook, where user can post feed, upload images

## Stack details
```bash
Framework : python-Django
version : Django-1.9.8

Database:
Db : sqlite (default)

Backend:
Language : python
verison : python3

Front-end:
HTML : HTML5
css : bootstrap4
js

Log file:
location : /var/log/mock_fb.log 

Hostname:
host : localhost (default)
```
## Installation


```bash
git clone https://github.com/goutham9032/Mockfb.git
cd Mockfb
```

```bash
pip3 install -r requirements.txt
```

```bash
python3 manage.py makemigrations
```

```bash
python3 manage.py migrate
```

```bash
python3 manage.py createinitialrevisions
python3 manage.py app.FeedActivity --comment="Initial revision."
# https://django-reversion.readthedocs.io/en/stable/api.html
# https://django-reversion.readthedocs.io/en/stable/commands.html#createinitialrevisions
# Note : please run these commands if you have any feeds
```

```bash
If you want send emails for OTP then user need to give his/her gmail credentials in local_settings.py
vim Mock_fb/local_settings.py 
# add these two lines with valid details and then save file
EMAIL_HOST_USER = 'xxxx@gmail.com' #my gmail username
EMAIL_HOST_PASSWORD = '******' #my gmail password
```

## Running Locally
```bash
python3 manage.py runserver 0:2222 
```
> Note: when you want to run this application on server, please add domain name/ip address in ALLOWEDHOSTS in settings.py

## In browser
```python
http://localhost:2222 
     or
http://<ipaddress/domain name>:2222 # when you are running on server
```

