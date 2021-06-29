# flask imports
from flask import Flask, request, jsonify, make_response,session,render_template,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
import executor as exc
import eval_jp

# creates Flask object
app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in session:
            token = session['x-access-token']
        #    token = session['token']
        print("hello hello")
        print (token)
        # return 401 if token is not passed
        if token == '':
            print("error in token")
            return jsonify({'message': 'Token is missing !!'}), 401
        try:
            # decoding the payload to fetch the stored details
            #data = jwt.decode(token, app.config['SECRET_KEY'])
            #current_user = User.query \
            #    .filter_by(public_id=data['public_id']) \
            #    .first()
            print ("in try block")
            #data = token
            print (token[0]['public_id'])
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        #output,errors = exc.execute("python eval_jp.py")
        return render_template("stock.html",output = eval_jp.main())


    return decorated


# User Database Route
# this route sends back list of users users
@app.route('/stock', methods=['GET'])
@token_required
def stock():
    # querying the database
    # for all the entries in it
    """
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'email': user.email
        })
    """
    #return jsonify({'users': output})

    return "Success"

@app.route('/', methods=['GET', 'POST'])
def home():
    """ Session control"""
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if request.method == 'POST':
            #data = eval_jp()
            return render_template('index.html')
        return render_template('register.html')


# route for loging user in
@app.route('/loggin', methods=['POST'])
def login():
    # creates dictionary of form data
    print ("hello")
    auth = request.form
    print (auth.get('email'),auth.get('password'))


    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query \
        .filter_by(email=auth.get('email')) \
        .first()
    #print (user.email)

    if not user:
        # returns 401 if user does not exist
        return render_template('register.html')
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = ({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        #return make_response(jsonify({'token': token}), 201).
        #session['token'] = token
        print (token)
        t = redirect(url_for('stock'))
        session['x-access-token'] = token
        return t
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    email =  data.get('email')
    password = data.get('password')
    print (email,password)

    # checking for existing user
    user = User.query \
        .filter_by(email=email) \
        .first()
    #print (user)
    if not user:
        # database ORM object
        user = User(
            public_id=str(uuid.uuid4()),
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


@app.route("/logout")
def logout():
    """Logout Form"""
    session['logged_in'] = False
    return redirect(url_for('home'))


if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    from login import db
    db.create_all()
    # if you hit an error while running the server
    app.run(debug=True)
