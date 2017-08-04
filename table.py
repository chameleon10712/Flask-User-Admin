import os
from flask import Flask, url_for, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

class Person:
	
	def __init__(self, name, email):
		self.name = name
		self.email = email


@app.route('/')
def table():

	p1 = Person('John Doe', 'johndoe@gmail.com')
	p2 = Person('Jane Doe', 'Janedoe@gmail.com')
	p_list = [p1, p2]
	return render_template('table.html', people = p_list)


if __name__ == '__main__':
	app.debug = True
	app.run(host='127.0.0.1')




