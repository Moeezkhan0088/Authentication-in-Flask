from flask import Flask, request, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)

# Correct configuration key and URI for SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Initialize SQLAlchemy
db = SQLAlchemy(app)

app.secret_key = 'secret_key'

class USER(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return 'Hi'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if the email already exists
        existing_user = USER.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error='Email already in use.')

        new_user = USER(name=name, email=email, password=password)
        db.session.add(new_user)
        try:
            db.session.commit()
            return redirect('/login')
        except Exception as e:
            db.session.rollback()  # Rollback the session in case of error
            return render_template('register.html', error='Registration failed. Please try again.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = USER.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid email or password')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:  # Check if the user is logged in
        user = USER.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html', user=user)
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
