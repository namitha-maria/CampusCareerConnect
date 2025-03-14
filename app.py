from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/student-login')
def student_login():
    return render_template('SL.html')

@app.route('/alumni-login')
def alumni_login():
    """ Alumni login page """
    return render_template('AL.html')

@app.route('/admin-login')
def admin_login():
    """ Admin login page """
    return render_template('ADL.html')

@app.route('/register')
def register():
    """ Registration page """
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
