from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path

import json

# Use bcrypt for password handling
import bcrypt

PASSWORDFILE = 'passwords.json'

PASSWORDFILEDELIMITER = ":"



app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
    with open(PASSWORDFILE, 'w') as f:
        json.dump({'Users': []}, f, indent=4)


@app.route('/')
def home():
    # Checking to see if session has a username connected to it
    if not session.get("USERNAME") is None:
        # If it does, the user has logged in and will get the loggedin.html
        username = session.get("USERNAME")
        return render_template('loggedin.html', username=username)
    # If the user is not, he is sent to the home.html
    else:
        return render_template('home.html')


# Display register form
@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')

# A function to check if the username is already in use
def check_username(username):
    with open(PASSWORDFILE, 'r') as f:
        file_data = json.load(f)
        # Checking every user in the database
        for i in file_data['Users']:
            # If the username is in the database, return false
            if i['username'] == username:
                return False
        # Else, return true
        return True

# Handle registration data
@app.route('/register', methods=['POST'])
def register_post():
    # Extract the information the user typed in to the different boxes
    username = request.form['username']
    password = request.form['password']
    matchpassword = request.form['matchpassword']

    # If the user has not entered a username
    if username == '':
        return render_template('register.html', error="You need to enter a username")
    # If the username already exist
    if not check_username(username):
        # Return to the user that the username is unavaliable
        return render_template('register.html', error="Username already registered")
    else:
        # Checking if the passwords match
        if password == matchpassword:
            # Checking that the passwords meets a set of credentials
            if len(password) < 6:
                return render_template('register.html', error="Password is too short")
            if not any(char.isdigit() for char in password):
                return render_template('register.html', error="Password needs to have atleast one number")
            if not any(char.islower() for char in password):
                return render_template('register.html', error="Password needs to have atleast one lower case letter")
            if not any(char.isupper() for char in password):
                return render_template('register.html', error="Password needs to have atleast one upper case letter")

            else:
                #Generate salt and hashed used to encrypt the password using bcrypt
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

                # creating a json object that includes the username and the hashed password
                json_object = {
                    'username': username,
                    'password': hashed.decode('utf-8'),
                    }   
                # First we open the passwords.json file to extract the information that is stored there
                with open(PASSWORDFILE, 'r') as f:
                    file_data = json.load(f)
                # Then we open the file again to write data to the file.
                with open(PASSWORDFILE, 'w') as f:
                    # appends the new data to the file. Also makes sure that the information is stored inside "users" 
                    file_data['Users'].append(json_object)
                    json.dump(file_data, f, indent=4)

                # Return the user to the login html so that they can login with their new user
                return redirect('/login')

        else:
            # If the passwords doesn't match, return an error saying so
            return render_template('register.html', error="Passwords doesn't match")


# Display login form
@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


# Handle login credentials
@app.route('/login', methods=['POST'])
def login_post():
    # Get the username and password the user typed in
    username = request.form['username']
    password = request.form['password']

    # Open the json file passwords.json
    with open(PASSWORDFILE, 'r') as f:
        file_data = json.load(f)

    # For every user registered in the file
    for i in file_data['Users']:
        # If the username is the same as another username
        if i['username'] == username:
            # encode both passwords
            hashed_pw = i['password'].encode('utf-8')
            password = password.encode('utf-8')
            # Check if the passwords match. checkpw returns a true if it does
            if bcrypt.checkpw(password, hashed_pw):
                session["USERNAME"] = i['username']
                return redirect('/')
    return render_template('login.html', error="Wrong username or password")


if __name__ == '__main__':
    app.run(debug=True)

    # This is how the app runs on my server. 
    # app.run(debug=True, ssl_context=('/home/ubuntu/ca/fullchain.pem', '/home/ubuntu/ca/privkey.pem'))
