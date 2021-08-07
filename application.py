from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from flask_mail import Mail, Message
from cs50 import SQL
import datetime
import os, string
from random import *
from helpers import login_required
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash


# Configuration:
app = Flask(__name__)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///admin.db")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Mail Configuration

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = 'abcnkv4suryansh@gmail.com'
app.config['MAIL_PASSWORD'] = '1234asuryansh'
app.config["MAIL_DEFAULT_SENDER"] = 'abcnkv4suryansh@gmail.com'
app.config['MAIL_USE_TLS'] = True

mail = Mail(app)

# ROUTES

# ROUTE -- Index
@app.route("/")
def index():

    return render_template("index.html")

# ROUTE -- Gallery
@app.route("/gallery")
def gallery():
    return render_template("gallery.html")


# ROUTE -- FAQ

# FAQ -- User Comments
@app.route("/FAQ/comments", methods=["GET", "POST"])
def user_comments():
    if request.method == "POST":

        name = request.form.get("name")
        mail = request.form.get("email")
        comment = request.form.get("comment")
        time_stamp = datetime.datetime.now()

        # Error check :
        if not name or not mail or not comment:
            return 'Error'

        db.execute("INSERT INTO comments (name, comment, time_stamp, mail) VALUES (?, ?, ?, ?)", name, comment, time_stamp, mail)

        return render_template("received.html")

    else:

        comments = db.execute("SELECT * FROM comments")
        answers = db.execute("SELECT * FROM answers")

        return render_template("FAQ/comments.html", comments=comments, answers= answers)


# FAQ -- General
@app.route("/FAQ/general")
def general():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "general" + "%")
    return render_template("FAQ/faq.html", data=data)

# FAQ -- Departments
@app.route("/FAQ/departments")
def departments():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "departments" + "%")
    return render_template("FAQ/faq.html", data=data)

# FAQ -- Hostels
@app.route("/FAQ/hostels")
def hostels():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "hostels" + "%")
    return render_template("FAQ/faq.html", data=data)

# FAQ -- Society
@app.route("/FAQ/society")
def society():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "society" + "%")
    return render_template("FAQ/faq.html", data=data)


# ADMIN CONTROLS

# ROUTE -- Admin
@app.route("/admin")
@login_required
def admin():
    comments = db.execute("SELECT * FROM comments")
    answers = db.execute("SELECT * FROM answers")
    flag = db.execute("SELECT admin from admin")
    flag = flag[0]["admin"]
    return render_template("Admin/admin_dasboard.html", comments=comments, answers=answers, flag=flag)


# ROUTE -- Login (Admin)
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username");
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return 'Please Enter a username'

        # Ensure password was submitted
        elif not password:
            return 'Please enter the Password'

        # Query database for username
        rows = db.execute("SELECT * FROM admin WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return 'Invalid Username or Password'

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to admin-home page
        return redirect("/admin")

    # User reached route
    else:
        return render_template("Admin/login.html")


# ROUTE -- Logout (Admin)
@app.route("/admin/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/admin/login")

# ROUTE -- Register (Admin)
@app.route("/admin/register", methods=["GET", "POST"])
@login_required
def register():

    if request.method == "GET":
        session_id = session["user_id"]

        # Check the flag for super-admin
        flag = db.execute("SELECT admin FROM admin WHERE id = ?", session_id)
        flag = flag[0]["admin"]

        if flag != 1:
            return '***UNAUTHORISED ACCESS***'
        else:
            return render_template("Admin/register.html")

    else:

        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # ERROR CHECK -- Name

        # Blank name
        if not name:
            return 'Please enter a name'

        # Name as spaces
        if(username.strip() == ""):
            return 'Please enter a name'

        # ERROR CHECK -- Username

        # blank username:
        if not username:
            return 'Please enter a username'

        # username already exsists:
        users = db.execute("SELECT username FROM admin")
        for user in users:
            if username == user["username"]:
                return 'Username already exsists'

        # username as spaces
        if(username.strip() == ""):
            return 'Please enter a username'

        # ERROR CHECK -- Password

        # blank password
        if not password:
            return 'Please enter a password'

        # password and confimation not match
        if password != confirmation:
            return "Passwords do not match"

        # password as spaces
        if(password.strip() == ""):
            return 'Please enter a password'

        # REGISTERING THE INFORMATION

        # Hashing password
        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)


        db.execute("INSERT INTO admin (name, username, password, mail) VALUES (?, ?, ?, ?)", name, username, hashed, email)

        return render_template("received.html")


# ROUTE -- FAQ (Admin)

# FAQ -- General (Admin)
@app.route("/admin/faq/general")
def admin_general():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "general" + "%")
    return render_template("Admin/show_faq.html", data=data)

# FAQ -- Departments (Admin)
@app.route("/admin/faq/departments")
def admin_departments():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "departments" + "%")
    return render_template("Admin/show_faq.html", data=data)

# FAQ -- Hostels (Admin)
@app.route("/admin/faq/hostels")
def admin_hostels():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "hostels" + "%")
    return render_template("Admin/show_faq.html", data=data)

# FAQ -- Society (Admin)
@app.route("/admin/faq/society")
def admin_society():

    data = db.execute("SELECT questions,answers FROM faq WHERE tags LIKE ?", "%" + "society" + "%")
    return render_template("Admin/show_faq.html", data=data)

# ROUTE -- Delete (Admin)
@app.route("/admin/delete", methods=["POST"])
@login_required
def delete():
    sl_id = request.form["id"]

    if (sl_id):
        db.execute("DELETE FROM answers WHERE sl_no = ?", sl_id)
        db.execute("DELETE FROM comments WHERE sl_no = ?", sl_id)

    return jsonify({'status':'ok'})

# ROUTE -- Reply (Admin)
@app.route("/admin/reply", methods=["GET", "POST"])
@login_required
def reply():

    if request.method == "POST":
        name = request.form.get("name")
        mail = request.form.get("email")
        comment = request.form.get("comment")
        id = request.args.get("id")
        time = datetime.datetime.now()

        if not id:
            return 'error'
        db.execute("INSERT INTO answers(sl_no, name, comment, time_stamp, mail) VALUES (?, ?, ?, ?, ?)", id, name, comment, time, mail)
        return redirect("/admin")
    else:

        id = session["user_id"]
        sl_no = request.args.get("id")

        if not sl_no:
            return 'error'

        com = db.execute("SELECT * FROM comments WHERE sl_no = ?", sl_no)
        com = com[0]
        data = db.execute("SELECT * FROM admin WHERE id = ?", id)
        data = data[0]

        return render_template("Admin/reply.html", data=data, com=com)

# ROUTE -- Add FAQ (Admin)
@app.route("/admin/faq/add", methods=["POST"])
@login_required
def add_faq():

    question = request.form.get("question")
    answer = request.form.get("answer")
    options = request.form.getlist('options')
    path = request.url
    tags = ""
    id = session["user_id"]

    # ERROR CHECK
    if not question:
        return 'Please Enter A Question'

    if not answer:
        return 'Please Enter An Answer'

    if len(options) == 0:
        return 'Please Select Atleast One Option'

    for items in options:
        tags = tags + items + ","

    data = db.execute("SELECT * FROM admin WHERE id = ?", id)
    data = data[0]
    db.execute("INSERT INTO faq (name, mail, questions, answers, tags) VALUES (?, ?, ? , ?, ?)", data["name"], data["mail"], question, answer, tags)

    return redirect("/admin")

# ROUTE -- Delete FAQ (Admin)
@app.route("/admin/faq/delete", methods=["GET", "POST"])
@login_required
def delete_faq():

    if request.method == "POST":

        tag = request.form.get("opt")
        question = request.form.get("question")
        question = int(question)

        # ERROR CHECK

        # FAQ Exsist ?
        sl_nos = db.execute("SELECT sl_no FROM faq")
        l = []
        for row in sl_nos:
            l.append(row["sl_no"])

        if not question in l:
            return 'ERROR - Please Resubmit The Form'

        # FAQ Exsisting On Multiple Pages
        tags = db.execute("SELECT tags FROM faq WHERE sl_no = ?", question)
        tags = tags[0]["tags"]
        l = tags.split(',')

        if len(l) == 1:
            # Deleting The Complete Row
            db.execute("DELETE FROM faq WHERE sl_no = ?", question)
        else:
            l.remove(tag)
            l.pop(-1)
            tags = ""
            for data in l:
                    tags += data + ","

            # Deleting The Tag so (FAQ will be visibli in other pages)
            db.execute("UPDATE faq SET tags = ? WHERE sl_no = ?", tags, question)
            return redirect("/admin/faq/general")

    else:
        option = request.args.get("opt")

        data = db.execute("SELECT sl_no, questions FROM faq WHERE tags LIKE ?", "%" + option +"%")

        return jsonify(data)

# ROUTE -- Profile (Admin)
@app.route("/admin/profile")
@login_required
def profile():

    id = session["user_id"]

    data = db.execute("SELECT * FROM admin WHERE id = ?", id)
    data = data[0]

    faq = db.execute("SELECT COUNT(sl_no) FROM faq")
    faq = faq[0]["COUNT(sl_no)"]

    com = db.execute("SELECT COUNT(sl_no) FROM comments")
    com = com[0]["COUNT(sl_no)"]
    ans = db.execute("SELECT COUNT(sl_no) FROM answers")
    ans = ans[0]["COUNT(sl_no)"]

    count = int(com - ans)
    return render_template("/Admin/profile.html", data=data, faq=faq, count=count)


# ROUTE -- Change Password (Admin)
@app.route("/admin/change_password", methods=["GET", "POST"])
def chnage_password():

    if request.method == "GET":
        return render_template("/Admin/password_change.html")

    else:
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        id = session["user_id"]

        # ERROR CHECK -- Password

        # blank password
        if not password:
            return 'Please enter a password'

        # password and confimation not match
        if password != confirmation:
            return "Passwords do not match"

        # password as spaces
        if(password.strip() == ""):
            return 'Please enter a password'

        # REGISTERING THE INFORMATION

        # Hashing password
        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        ### MAIL ###

        db.execute("UPDATE admin SET password = ? WHERE id = ?", hashed, id)

        return redirect("/admin/login")


# ROUTE -- Forgot password ERROR NOT WORKING
@app.route("/admin/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "GET":
        return render_template("/Admin/forgot_password.html")

    else:

        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")

        # ERROR CHECK -- name

        # Blank name
        if not name:
            return 'PLease enter a name'

        # Name as spaces
        if(name.strip() == ""):
            return 'Please enter a name'

        # ERROR CHECK -- Username

        # Blank name
        if not username:
            return 'Please enter a username'

        # Name as spaces
        if(username.strip() == ""):
            return 'Please enter a username'

        # Matching data in the database :

        data = db.execute("SELECT * FROM admin where username = ? OR mail = ?", username, email)

        if len(data) != 1:
            return 'You registration was not found ! Please check your username and email address.'

        else:

            # Generating random  OTP
            otp = randint(000000,999999)

            # Hashing otp
            #hashed = generate_password_hash(otp, method='pbkdf2:sha256', salt_length=8)

            # Changing the password with the otp
            #db.execute("UPDATE admin SET passowrd = ? WHERE username = ? OR mail = ?", hashed, username, email)

            # Mail -- ERROR NOT WORKING
            re = data[0]["mail"]
            msg = Message("OTP", recipients = ['sonogo6850@dedatre.com'])
            msg.body = f"Dear user, Please use otp:{otp} to login to your CU Helpdesk admin account and change your account password in the profile"
            mail.send(msg)

            return 'Message sent !'

# ROUTE -- Reply
# @app.route("/admin/reply", methods=["GET", "POST"])
# @login_required
# def reply():

# TRY
@app.route("/try", methods=["GET", "POST"])
def trry():
    return render_template("FAQ/try.html")