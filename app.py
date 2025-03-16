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
@app.route('/mock_interview')
def mock_interview():
    """ mockinterview page """
    return render_template('AMI.html')
@app.route('/q_a')
def q_a():
    """ Q&A page """
    return render_template('q_a.html')
@app.route('/alumni_direc')
def alumni_direc():
    """ alumni_directory page """
    return render_template('alumni_direc.html')
@app.route('/apt_test')
def apt_test():
    """ aptitude_test page """
    return render_template('AdminAT.html')
@app.route('/code_challenge')
def code_challenge():
    """ coding_challenges page """
    return render_template('AdminCC.html')
@app.route('/stud_progress')
def stud_progress():
    """ student_progress page """
    return render_template('AdminPD.html')

if __name__ == '__main__':
    app.run(debug=True)
