from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', title="Welcome")

@app.route('/home')
def home():
    return render_template('home.html', message="This is the home page!")

if __name__ == '__main__':
    app.run(debug=True)  # Set debug=False in production
