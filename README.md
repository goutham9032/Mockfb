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
```

```bash
pip3 install -r requirements.txt
```

```bash
python3 manage.py migrate
```

```bash
python3 manage.py runserver
```

```bash
python3 manage.py createsuperuser
```

```python
python3 manage.py shell
>>> from django.contrib.auth.models import User
>>> User.objects.filter(id=1).update(first_name="Anjelina John")
```

## Running Locally
```bash
python3 manage.py runserver 0:2222 
```
> Note: when you want to run this application on server, please add domain name/ip address in ALLOWEDHOSTS in settings.py

## In browser
```python
http://localhost:2222
```

