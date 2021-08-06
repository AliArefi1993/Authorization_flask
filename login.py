from datetime import timedelta
from werkzeug.security import generate_password_hash,check_password_hash
import sqlite3
from flask import Flask, request
from flask import jsonify
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)

    #login user and sed access and refresh tokens
@app.route("/login", methods=["POST"])
def login():
        # check validation of usernae and password by Basic Auth
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response({'message': 'usename and password is required', 'result': 0})
    rows = view()
    for row in rows:
        if (auth.username in row["username"]) and  check_password_hash(row["password"],auth.password):
            access_token = create_access_token(identity=row["username"])
            refresh_token = create_refresh_token(identity=row["username"])
            response = jsonify(access_token=access_token,  refresh_token=refresh_token)
    return response

    #add new user
@app.route('/adduser', methods=['POST'])
def add_user():
   data = request.get_json()
   username = data['username']
   password = data['password']
   email = data['email']
   addnewuser(username, password, email)
   response = jsonify({'message': 'new user added successfully', 'result': 1})
   return response

   #get information of each user by username
@app.route('/user', methods=['GET'])
def get_all_users():
    username = request.args.get('username')
    rows = view()
    result = []
    for row in rows:
        if row['username']== username:
            user_data = {}
            user_data['username'] = row['username']
            user_data['email'] = row['email']
            result.append(user_data)
    return jsonify({'users': result})

    #get new access token by refresh token
    # We are using the `refresh=True` options in jwt_required to only allow
    # refresh tokens to access this route.
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

    #edit information of logged in user
@app.route("/edit", methods=["POST"])
@jwt_required()
def edit():
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        for type in data:
            if type=="email":
                edit_email(data['email'], current_user)
                return jsonify({'message' : 'email edited'})
            elif type=="username":
                edit_user(data['username'], current_user)
                return jsonify({'message' : 'username edited'})
            elif type=="password":
                edit_password(data['password'], current_user)
                return jsonify({'message' : 'password edited'})
    except:
        return jsonify({'message' : 'noting happened'})


#DATABASE = 'E:\PRO\PRJ\Flask\login_prj/database.db'
#sqlite3.connect(DATABASE)
conn = sqlite3.connect('database.db')
        #Initiate a database with 2 user (if dosen't exist)

try:
    conn.execute('CREATE TABLE users (username, password, email)')
    print("Table created successfully")
    cur = conn.cursor()
    hashed_password = generate_password_hash('1234', method='sha256')
    cur.execute("INSERT INTO users (username, password, email)VALUES (?,?,?)",("Ali",hashed_password,"Ali@yahoo.com") )
    hashed_password = generate_password_hash('5678', method='sha256')
    cur.execute("INSERT INTO users (username, password, email)VALUES (?,?,?)",("Reza",hashed_password,"Reza@gmail.com") )
    conn.commit()
    print("Record successfully added")

        #use of existeddatabase
except:
    print("Table already has been created successfully")

    # View all database users information
def view():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("select * from users")
    rows = cur.fetchall()
    return rows

    # sighnup new user
def addnewuser(username, password, email):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    hashed_password = generate_password_hash('1234', method='sha256')
    cur.execute("INSERT INTO users (username, password, email)VALUES (?,?,?)",(username,hashed_password,email) )
    conn.commit()
    conn.close()

    #edit user username
def edit_user(title, current_user):
    conn = sqlite3.connect('database.db')
            # Getting cursor
    c =  conn.cursor()
            # Editing em
    c.execute("UPDATE users SET username = ? WHERE username = ?" ,(title, current_user))
        # Applying changes
    conn.commit()
    conn.close()
    #edit user password
def edit_password(title, current_user):
    conn = sqlite3.connect('database.db')
            # Getting cursor
    c =  conn.cursor()
            # Editing em
    hashed_password = generate_password_hash(title, method='sha256')
    print(hashed_password)
    c.execute("UPDATE users SET password = ? WHERE username = ?" ,(hashed_password, current_user))
        # Applying changes
    conn.commit()
    conn.close()

        #edit user email
def edit_email(title, current_user):
    conn = sqlite3.connect('database.db')
            # Getting cursor
    c =  conn.cursor()
            # Editing em
    c.execute("UPDATE users SET email = ? WHERE username = ?" ,(title, current_user))
        # Applying changes
    conn.commit()
    conn.close()

    # run app
if __name__ == "__main__":
    app.run()
