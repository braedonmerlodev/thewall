from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from datetime import datetime
import os, binascii
import re
import md5
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

app = Flask(__name__)
mysql = MySQLConnector(app,'walldb')
app.secret_key = "abcde1234"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/wall')
    else:
        return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT  * FROM USERS WHERE users.email = :email LIMIT 1"
    query_data = {'email': email}
    user = mysql.query_db(user_query, query_data)
    if len(user) != 0:
        encrypted_password = md5.new(password + user[0]['salt']).hexdigest()
        if user[0]['password'] == encrypted_password:
            session['user_id'] = user[0]['id']
            session['first_name'] = user[0]['first_name']
            session['last_name'] = user[0]['last_name']
            return redirect('/wall')
    flash("Incorrect Username/Password")
    return redirect('/')

@app.route('/register', methods=['POST'])
def create():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    errors = []
    if len(request.form['first_name']) < 2 and len(request.form['last_name']) < 2:
        errors.append('Error! This field requires as least two characters')
        
    elif not EMAIL_REGEX.match(request.form['email']):
        errors.append('Invalid email format. Please try again')

    elif len(request.form['password']) < 8 and len(request.form['pw_confirm']) < 8:
        errors.append('Your password must be more than eight characters.')

    elif request.form['password'] != request.form['pw_confirm']:
        errors.append('Your passwords must match')

    if not errors:
       duplicate = mysql.query_db("SELECT * FROM users WHERE email = :email", {'email': email})
       if duplicate:
           errors.append('This email address already exists')

    if errors:
        for error in errors:
            flash(error, 'error!')
        return redirect('/')

    salt = binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(password + salt).hexdigest()
    insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"
    query_data = { 'first_name': first_name, 'last_name': last_name, 'email': email, 'password': hashed_pw, 'salt': salt}
    mysql.query_db(insert_query, query_data)
    flash("Successfully Registered", "Success")
    return redirect('/wall')

@app.route('/wall')
def wall():
    messages_query = "SELECT first_name, last_name, message, DATE_FORMAT(messages.created_at, '%M %D %Y %H:%i') AS created_at, messages.id, user_id FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
    display_messages = mysql.query_db(messages_query)
    comments_query = "SELECT first_name, last_name, comment, DATE_FORMAT(comments.created_at, '%M %D %Y %H:%i') AS created_at, message_id FROM comments JOIN users ON comments.user_id = users.id ORDER BY comments.created_at"
    display_comments = mysql.query_db(comments_query)
    return render_template('wall.html', display_messages = display_messages, display_comments = display_comments)

@app.route('/wall/message', methods=['POST'])
def message():
    message = request.form['message']
    current_session = session['user_id']
    message_query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message, NOW(), NOW(), :current_session)"
    query_data = {'current_session': current_session, 'message': message}
    mysql.query_db(message_query, query_data)
    return redirect('/wall')

@app.route('/wall/comment/<message_id>', methods=['POST'])
def comment(message_id):
    current_session = session['user_id']
    comment = request.form['comment']
    comment_query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES (:comment, NOW(), NOW(), :current_session, :message_id)"
    query_data = {
        'comment': comment,
        'current_session': current_session,
        'message_id': message_id
        }
    mysql.query_db(comment_query, query_data)
    return redirect('/wall')

@app.route('/logout', methods=['GET'])
def logout():
    del session['user_id']
    return redirect('/')

@app.route('/wall/message/delete/<id>')
def delete_comment(id):
    del_comments_query = "DELETE FROM comments WHERE message_id = :id"
    data = {
        'id': id
    }
    mysql.query_db(del_comments_query, data)
    del_message_query = "DELETE FROM messages WHERE id = :id"
    mysql.query_db(del_message_query, data)
    return redirect('/wall')

app.run(debug=True)


