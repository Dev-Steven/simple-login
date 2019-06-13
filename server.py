from flask import Flask, render_template, request, redirect, flash, url_for, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'keep it secret'
bcrypt = Bcrypt(app)

EMAIL_RE = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_RE = re.compile(r'^[A-Za-z]+$')

USER_KEY = "user_id"

@app.route('/')
def login_reg():
    session.clear()
    return render_template("index.html")


@app.route('/login', methods=['POST'])
def login():
    provided_email = request.form['email']
    provided_password = request.form['password']

    # is the email that was entered in the database?
    query = "SELECT password, id FROM users WHERE email = %(em)s"
    thesql = connectToMySQL("login_reg_db")
    data = {"em": request.form["email"]}
    print(data)
    result = thesql.query_db(query, data)
    print("email check:", result)

    # if the email is in the database does the password in the db match the one given
    if result:
        print(bcrypt.check_password_hash(result[0]['password'], provided_password))
        pw_verify = bcrypt.check_password_hash(result[0]['password'], provided_password)
        if pw_verify == False:
            flash("Wrong information, try again")
            redirect("/")
        else: 
            session[USER_KEY] = result[0]["id"]
            return redirect("/success")

    return redirect("/")



@app.route('/register', methods=['POST'])
def register():
    # validations
    is_valid = True

    # first name validation
    provided_fn = request.form['first_name']
    if len(provided_fn) < 2:
        is_valid = False
        flash("First name must be at least 2 characters")
    if not NAME_RE.match(provided_fn):
        flash("First name must only be letters")

    # last name validation
    provided_ln = request.form['last_name']
    if len(provided_ln) < 2:
        is_valid = False
        flash("Last name must be at least 2 characters")
    if not NAME_RE.match(provided_ln):
        flash("Last name must only be letters")

    # start of email validation

    # getting email from the index.html page
    provided_email = request.form['email'] 
    # checking to see if this email is not already in the db
    query = 'SELECT password FROM users WHERE email = %(em)s'
    data = { 'em': provided_email }
    mysql = connectToMySQL('login_reg_db')
    result = mysql.query_db(query, data)
    print("This is the result: ", result)

    if not EMAIL_RE.match(provided_email):
        flash("Email is invalid")

    # the result is a list and there can only to one item of that specific email in the list
    if(len(result) > 0):
        flash("Email already used")

    # password validation
    provided_pw = request.form['password']
    if len(provided_pw) < 8:
        is_valid = False
        flash("Password must be at least 8 characters")

    #password confirmation
    confirm_pw = request.form['confirmed']
    if confirm_pw != provided_pw:
        is_valid = False
        flash("Passwords do not match")

    if "_flashes" in session:
        return redirect('/')

    else:
        # all validations passed, so add the user to the database
        mysql2 = connectToMySQL('login_reg_db')

        # hash the password
        hashed_pw = bcrypt.generate_password_hash(request.form['password'])
        
        insert_data = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW())"

        data = {
            "fn": request.form["first_name"],
            "ln": request.form["last_name"],
            "em": request.form["email"],
            "pw": hashed_pw,
        }
        print(data)

        new_user = mysql2.query_db(insert_data, data)
        session[USER_KEY] = new_user
        print(new_user)
        return redirect('/success')

    return redirect('/')


@app.route('/success')
def success():
    if not USER_KEY in session:
        return redirect('/')
    mysql = connectToMySQL('login_reg_db')
    user = mysql.query_db('SELECT * FROM users WHERE id = %(id)s', {'id': session[USER_KEY]})
    return render_template('success.html', all_users = user)


if __name__ == "__main__":
    app.run(debug=True)