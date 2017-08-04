"""Flask Login Example"""
import os
from flask import Flask, url_for, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)


class User(db.Model):
	""" Create user table"""

	__tablename__ = 'User'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True)
	password = db.Column(db.String(80))

	def __init__(self, username, password):
		self.username = username
		self.password = password

class Role(db.Model):

    __tablename__ = 'Role'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(255), nullable=False)

    def __init__(self, role):
        self.role = role


class UserRole(db.Model):

    __tablename__ = 'UserRole'
    id = db.Column(db.Integer, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey('Role.id'), nullable=False)

    def __init__(self, u_id, role_id):
        self.u_id = u_id
        self.role_id = role_id



@app.route('/', methods=['GET', 'POST'])
def home():
	""" Session control"""
	if session.get('logged_in'):
		return redirect(url_for('hello', username=session['logged_in']))
	else:
		return render_template('index.html')

@app.route('/hello')
@app.route('/hello/<username>')
def hello(username=None):
	if session.get('logged_in') != username:
		return redirect(url_for('home'))
	else:
		return render_template('index.html', username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
	"""Login Form"""
	if request.method == 'GET':
		if session.get('logged_in'):
			return redirect(url_for('hello', username=session['logged_in']))
		else:
			return render_template('login.html')
	else:
		name = request.form['username']
		passwd = request.form['password']
		data = User.query.filter_by(username=name).first()
		true_user = check_password_hash(data.password, passwd)
		if true_user:
			session['logged_in'] = name
			return redirect(url_for('hello', username=name))
		else:
			return 'User not exists'


@app.route('/register/', methods=['GET', 'POST'])
def register():
	"""Register Form"""
	if request.method == 'POST':
		usr_passwd = generate_password_hash(request.form['password'])
		new_user = User( username = request.form['username'], password = usr_passwd)
		db.session.add(new_user)
		db.session.commit()
		return render_template('login.html')

	return render_template('register.html')

@app.route("/logout")
def logout():
	"""Logout Form"""
	del session['logged_in']
	return redirect(url_for('home'))


@app.route('/user_list')
def user_list():
	people = db.session.query(User.id, User.username).all()	
	people = sorted(people, key=lambda person: person[0])
	return render_template('table.html', people = people)


@app.route('/delete_user', methods=['POST'])
def delete_user():

	u_id = int(request.form['u_id'])	
	instance = User.query.filter_by(id = u_id).first()
	print(instance.username)

	db.session.delete(instance)
	db.session.commit()

	return 'ok'

@app.route('/add_user' , methods=['POST'])
def add_user():

	name = request.form['username']
	#check if username exist
	data = User.query.filter_by(username=name).first()
	if data is not None:
		return 'user name exist'

	tmp_passwd = os.urandom(24)	
	usr_passwd = generate_password_hash( tmp_passwd )
	new_user = User( username = name, password = usr_passwd)
	db.session.add(new_user)
	db.session.commit()
	
	return redirect(url_for('user_list'))

@app.route('/get_user_info', methods=['GET', 'POST'])
def get_user_info():

		
	return 'ok'

@app.route('/user_info')
def user_info():

	return render_template('user_info.html')


@app.route('/course_admin')
def course_admin():
	
	return render_template('course_admin.html')



@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
	# clear browser cache
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r


app.secret_key = os.urandom(24)

if __name__ == '__main__':
	app.debug = True
	db.create_all()
	app.secret_key = "123"
	app.run(host='127.0.0.1')
	

