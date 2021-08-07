# Enter the info here
import os, random, string
from werkzeug.security import check_password_hash, generate_password_hash
from application import db

name = "Suryansh B Verma"
username = "Suryansh"
email = "abcnkv@gmail.com"
password = "1234"
# REGISTERING THE INFORMATION

# Hashing password
hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

# Generating random admin table password (One can edit only with this password)
length = 13
chars = string.ascii_letters + string.digits + '!@#$%^&*()'
random.seed = (os.urandom(1024))
random_pass = ''.join(random.choice(chars) for i in range(length))

# Hashing random password
random_pass = generate_password_hash(random_pass, method='pbkdf2:sha256', salt_length=8)

db.execute("INSERT INTO admin (name, username, password, mail, admin_table_password) VALUES (?, ?, ?, ?, ?)", name, username, hashed, email, random_pass)