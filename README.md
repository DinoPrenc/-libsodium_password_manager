# Password manager for college final project

## How to use
Install dependencies from requirements file

Recommended using virtualenv

example: ``python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt``

After installing dependencies you can run client app and/or server app
### Client app
For client app just run client.py (Note: OS with UI is needed to run client app)

### Server app
To use Online mod you need to start server.py
set FLASK_APP environment variable:
``export FLASK_APP=server.py``  (Linux and MacOS)
Run ``flask run`` command

You can also run with python ``server.py`` without setting up environment variable(Note that some functionalities will be limited)