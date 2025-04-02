from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_bcrypt import Bcrypt
import mysql.connector
import json
import datetime
import requests
import base64
import os

# Judge0 API configuration
JUDGE0_API_URL = "https://judge0-ce.p.rapidapi.com"  # Or your self-hosted instance URL
JUDGE0_API_KEY = "3b06e27ce4msh0cf46f99a92d4f1p1251a4jsn92e125f549ba"  # Replace with your actual API key

# Language ID mapping for Judge0
LANGUAGE_IDS = {
    "python": 71,  # Python 3
    "java": 62,    # Java 13
    "cpp": 54,     # C++ 17
    "c": 50,       # C (GCC 9.2.0)
    "javascript": 63,  # JavaScript Node.js
    "csharp": 51,  # C# Mono
}

def submit_to_judge0(source_code, language_id, stdin=""):
    payload = {
        "source_code": source_code,  # Remove base64.b64encode()!
        "language_id": language_id,
        "stdin": stdin,  # Remove base64 encoding here too
        "cpu_time_limit": 5,
        "memory_limit": 256000
    }
    
    headers = {
        "X-RapidAPI-Key": JUDGE0_API_KEY,
        "X-RapidAPI-Host": "judge0-ce.p.rapidapi.com",
        "Content-Type": "application/json"
    }

    
    # Submit the code
    try:
        response = requests.post(
            f"{JUDGE0_API_URL}/submissions", 
            json=payload, 
            headers=headers
        )
        response.raise_for_status()
        submission = response.json()
        token = submission.get("token")
        
        if not token:
            return {"error": "Failed to submit code for execution"}
        
        # Get the submission result (with a small delay to allow processing)
        import time
        time.sleep(1)  # Wait for 1 second
        
        result_response = requests.get(
            f"{JUDGE0_API_URL}/submissions/{token}",
            headers=headers,
            params={"base64_encoded": "true", "fields": "*"}
        )
        result_response.raise_for_status()
        result = result_response.json()
        
        # Process and return the result
        processed_result = process_judge0_result(result)
        return processed_result
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Judge0 API Error: {str(e)}"}

def process_judge0_result(result):
    """Process the Judge0 API result"""
    # Status codes: https://github.com/judge0/judge0/blob/master/docs/api/submissions.md#submission-status
    status_map = {
        1: "In Queue",
        2: "Processing",
        3: "Accepted",
        4: "Wrong Answer",
        5: "Time Limit Exceeded",
        6: "Compilation Error",
        7: "Runtime Error (SIGSEGV)",
        8: "Runtime Error (SIGXFSZ)",
        9: "Runtime Error (SIGFPE)",
        10: "Runtime Error (SIGABRT)",
        11: "Runtime Error (NZEC)",
        12: "Runtime Error (Other)",
        13: "Internal Error",
        14: "Exec Format Error"
    }
    
    status_id = result.get("status", {}).get("id")
    status_description = status_map.get(status_id, "Unknown Status")
    
    # Decode outputs if they exist and are base64 encoded
    stdout = result.get("stdout")
    if stdout:
        stdout = base64.b64decode(stdout).decode('utf-8', errors='replace')
    else:
        stdout = ""
        
    stderr = result.get("stderr")
    if stderr:
        stderr = base64.b64decode(stderr).decode('utf-8', errors='replace')
    else:
        stderr = ""
        
    compile_output = result.get("compile_output")
    if compile_output:
        compile_output = base64.b64decode(compile_output).decode('utf-8', errors='replace')
    else:
        compile_output = ""
    
    # Time and memory usage
    time = result.get("time", "0")
    memory = result.get("memory", "0")
    
    return {
        "status": status_description,
        "status_id": status_id,
        "stdout": stdout,
        "stderr": stderr,
        "compile_output": compile_output,
        "time": time,
        "memory": memory,
        "success": status_id == 3  # Status 3 is "Accepted"
    }

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret key for session management
app.secret_key = 'your_secret_key'  # Change this to a secure key

# Function to get a database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Chinnu1811",
        database="CampusCareerConnect"
    )

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/studenthome')
def home2():
    return render_template('home2.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/student-login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['studentEmail']
        password = request.form['studentPassword']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  # Use dictionary cursor for better readability

        cursor.execute("SELECT * FROM Users WHERE Email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['Password'], password):  # Assuming 'Password' is the correct column name
            if user['Role'] == 'Student':  # Ensure role is 'Student'
                session['loggedin'] = True
                session['id'] = user['UserID']
                session['email'] = user['Email']
                session['role'] = user['Role']

                flash("Login successful!", "success")
                return redirect(url_for('home2'))  # Redirect to home after login
            else:
                flash("You are not registered as a student.", "danger")

        else:
            flash("Invalid email or password", "danger")

    return render_template('SL.html')  # Return login page on GET request or failed login

@app.route('/student-MI')
def student_MI():
    return render_template('MI.html')

#temporary
@app.route('/debug-questions')
def debug_questions():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM aptitude_test LIMIT 5")
    questions = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(questions)

#eoftemp

@app.route('/student-at')
def student_at():
     # or however you fetch questions
      # Debug: Check structure in terminal
    return render_template('AT.html')

@app.route('/student-cc')
def student_cc():
    return render_template('CC.html')

@app.route('/student-pd')
def student_pd():
    return render_template('PD.html')

@app.route('/student-ai')
def student_ai():
    return render_template('AI.html')

@app.route('/student-qna')
def student_qna():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT q.id, q.question_text, q.created_at, u.Name AS student_name,
               COALESCE(a.answer_text, '') AS answer_text, a.created_at AS answer_date, ua.Name AS alumni_name
        FROM questions q
        JOIN Users u ON q.user_id = u.UserID
        LEFT JOIN answers a ON q.id = a.question_id
        LEFT JOIN Users ua ON a.user_id = ua.UserID
        ORDER BY q.created_at DESC
    """)
    
    qna_data = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('Q&A.html', qna=qna_data)


@app.route('/ask-question', methods=['POST'])
def ask_question():
    if 'loggedin' not in session or session.get('role') != 'Student':
        flash("Only students can ask questions.", "danger")
        return redirect(url_for('student_qna'))

    question_text = request.form.get('question')
    if not question_text:
        flash("Question cannot be empty.", "danger")
        return redirect(url_for('student_qna'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO questions (user_id, question_text) VALUES (%s, %s)", 
                   (session['id'], question_text))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Your question has been posted!", "success")
    return redirect(url_for('student_qna'))
@app.route('/answer-question/<int:question_id>', methods=['POST'])
def answer_question(question_id):
    if 'loggedin' not in session or session.get('role') != 'Alumni':
        flash("Only alumni can answer questions.", "danger")
        return redirect(url_for('alumni_qna'))

    answer_text = request.form.get('answer')
    if not answer_text:
        flash("Answer cannot be empty.", "danger")
        return redirect(url_for('alumni_qna'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO answers (question_id, user_id, answer_text) VALUES (%s, %s, %s)", 
                       (question_id, session['id'], answer_text))
        conn.commit()
        flash("Your answer has been posted!", "success")
    except mysql.connector.Error as e:
        flash(f"Database Error: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('alumni_qna'))

@app.route('/student-ad')
def student_ad():
    return render_template('AD.html')

@app.route('/get_alumni')
def get_alumni():
    try:
        # Connect using your existing get_db_connection() function
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Updated query to match your actual schema:
        # - Uses Users table which we know exists (from your register route)
        # - Matches the alumni table structure you showed
        query = """
        SELECT 
            u.UserID,
            u.Name as name,
            a.grad_year,
            a.company,
            a.designation,
            a.bio
        FROM alumni a
        JOIN Users u ON a.UserID = u.UserID
        ORDER BY a.grad_year DESC
        """
        
        cursor.execute(query)
        alumni_data = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Enhanced response with success flag
        return jsonify({
            "success": True,
            "data": alumni_data
        })
    
    except mysql.connector.Error as e:
        print(f"MySQL Error fetching alumni data: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(e)}"
        }), 500
        
    except Exception as e:
        print(f"General Error fetching alumni data: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/alumni-login', methods=['GET', 'POST'])
def alumni_login():
    if request.method == 'POST':
        email = request.form['alumniEmail']
        password = request.form['alumniPassword']

        # Validate if email ends with '@rajagiri.edu.in'
        if not email.endswith('@rajagiri.edu.in'):
            flash("Alumni must use an email ending with @rajagiri.edu.in", "danger")
            return redirect(url_for('alumni_login'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM Users WHERE Email = %s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['Password'], password):  # Check password
            if user['Role'] == 'Alumni':  # Ensure it's an Alumni
                session['loggedin'] = True
                session['id'] = user['UserID']
                session['email'] = user['Email']
                session['role'] = user['Role']

                flash("Login successful!", "success")
                return redirect(url_for('home3'))  # Redirect to alumni dashboard
            else:
                flash("You are not registered as an Alumni.", "danger")
        else:
            flash("Invalid email or password", "danger")

    return render_template('AL.html')  # Render Alumni Login page

@app.route('/alumnihome')
def home3():
    if 'loggedin' in session and session.get('role') == 'Alumni':
        return render_template('home3.html')  # ✅ Ensure alumni get a dedicated homepage
    else:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('alumni_login'))  # Redirect to login if not logged in


@app.route('/alumni-MI')
def alumni_MI():
    return render_template('AMI.html')

# Changes needed for app.py:

@app.route('/alumni-qna')
def alumni_qna():
    # This route needs to fetch the Q&A data just like the student_qna route
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT q.id, q.question_text, q.created_at, u.Name AS student_name,
               COALESCE(a.answer_text, '') AS answer_text, a.created_at AS answer_date, ua.Name AS alumni_name
        FROM questions q
        JOIN Users u ON q.user_id = u.UserID
        LEFT JOIN answers a ON q.id = a.question_id
        LEFT JOIN Users ua ON a.user_id = ua.UserID
        ORDER BY q.created_at DESC
    """)
    
    qna_data = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('alqna.html', qna=qna_data)  # Pass the data to the template


@app.route('/alumni-ad')
def alumni_ad():
    return render_template('alAD.html')

@app.route('/alumni-about')
def alumni_about():
    return render_template('ALabout.html')



@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['adminEmail']
        password = request.form['adminPassword']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM Users WHERE Email = %s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['Password'], password):  # Check password
            if user['Role'] == 'Admin':  # Ensure it's an Admin
                session['loggedin'] = True
                session['id'] = user['UserID']
                session['email'] = user['Email']
                session['role'] = user['Role']

                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
            else:
                flash("You are not registered as an Admin.", "danger")
        else:
            flash("Invalid email or password", "danger")

    return render_template('ADL.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'loggedin' in session and session.get('role') == 'Admin':
        return render_template('ADC.html')  # Admin Dashboard
    #else:
     #   flash("Unauthorized access!", "danger")
    #    return redirect(url_for('admin_login')) 

@app.route('/admin-AT')
def admin_at():
    if 'loggedin' not in session or session.get('role') != 'Admin':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('admin_login'))
    return render_template('AdminAT.html')  # Admin interface to add questions

@app.route('/add_question', methods=['POST'])
def admin_add_question():
    if 'loggedin' not in session or session.get('role') != 'Admin':
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        # Handle form data (not JSON)
        qn_text = request.form.get('question', '').strip()
        options = {
            'A': request.form.get('optionA', '').strip(),
            'B': request.form.get('optionB', '').strip(),
            'C': request.form.get('optionC', '').strip(),
            'D': request.form.get('optionD', '').strip()
        }
        corr_opt = request.form.get('correctOption', '').strip().upper()

        # Validation
        if not qn_text:
            return jsonify({"success": False, "error": "Question text is required"}), 400
        if not all(options.values()):
            return jsonify({"success": False, "error": "All options are required"}), 400
        if corr_opt not in ['A', 'B', 'C', 'D']:
            return jsonify({"success": False, "error": "Correct option must be A, B, C, or D"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO aptitude_test 
            (qn_text, options, corr_opt) 
            VALUES (%s, %s, %s)""",
            (qn_text, json.dumps(options), corr_opt)
        )
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Question added successfully",
            "qn_id": cursor.lastrowid
        })

    except Exception as e:
        if conn and conn.is_connected():
            conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/get_questions', methods=['GET'])
def admin_get_questions():
    if 'loggedin' not in session or session.get('role') != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT qn_id, qn_text, options, corr_opt, 
                   DATE_FORMAT(test_date, '%Y-%m-%d %H:%i:%s') AS test_date 
            FROM aptitude_test 
            ORDER BY test_date DESC
        """)
        questions = cursor.fetchall()
        
        # Convert JSON options to dict
        for q in questions:
            q['options'] = json.loads(q['options'])
        
        return jsonify(questions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/delete_question', methods=['POST'])
def admin_delete_question():
    if 'loggedin' not in session or session.get('role') != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        qn_id = request.form.get('qn_id')
        if not qn_id:
            return jsonify({"error": "Question ID is required"}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete responses first to maintain referential integrity
        cursor.execute("DELETE FROM responses WHERE qn_id = %s", (qn_id,))
        # Then delete the question
        cursor.execute("DELETE FROM aptitude_test WHERE qn_id = %s", (qn_id,))
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Question {qn_id} and its responses deleted"
        })
    except Exception as e:
        if conn and conn.is_connected():
            conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# ----- Student Side -----

@app.route('/student/aptitude-test')
def student_aptitude_test():
    if 'loggedin' not in session or session.get('role') != 'Student':
        flash("Please login as student first", "danger")
        return redirect(url_for('student_login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get 10 random questions with formatted dates
        cursor.execute("""
            SELECT qn_id, qn_text, options, corr_opt,
                   DATE_FORMAT(test_date, '%Y-%m-%d') AS test_date 
            FROM aptitude_test 
            ORDER BY RAND() LIMIT 10
        """)
        questions = cursor.fetchall()
        
        # Convert options JSON to dict
        for q in questions:
            q['options'] = json.loads(q['options'])
        
        return render_template('AT.html', questions=questions)
    except Exception as e:
        flash(f"Error loading test: {str(e)}", "danger")
        return redirect(url_for('student_home'))
    finally:
        cursor.close()
        conn.close()

@app.route('/student/submit-answer', methods=['POST'])
def submit_answer():
    if 'loggedin' not in session or session.get('role') != 'Student':
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        data = request.get_json()
        qn_id = data.get('qn_id')
        selected_option = data.get('selected_option', '').upper()
        user_id = session['id']

        if not qn_id or not selected_option:
            return jsonify({"success": False, "error": "Missing question ID or selected option"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get correct answer
        cursor.execute(
            "SELECT corr_opt FROM aptitude_test WHERE qn_id = %s", 
            (qn_id,)
        )
        question = cursor.fetchone()
        
        if not question:
            return jsonify({"success": False, "error": "Invalid question ID"}), 400

        is_correct = (selected_option == question['corr_opt'])
        score = 1 if is_correct else 0

        # Record response
        cursor.execute(
            """INSERT INTO responses 
            (user_id, qn_id, selected_option, score) 
            VALUES (%s, %s, %s, %s)""",
            (user_id, qn_id, selected_option, score)
        )
        conn.commit()
        
        return jsonify({
            "success": True,
            "is_correct": is_correct,
            "correct_option": question['corr_opt'],
            "score": score
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin-CC')
def admin_cc():
    return render_template('AdminCC.html')

@app.route('/api/coding-challenges', methods=['GET'])
def get_challenges():
    if 'loggedin' not in session:
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, title, description, input_format, 
                   DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at 
            FROM coding_challenges
            ORDER BY created_at DESC
        """)
        challenges = cursor.fetchall()
        
        return jsonify(challenges)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/coding-challenges', methods=['POST'])
def add_challenge():
    if 'loggedin' not in session or session.get('role') != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        title = request.form.get('title')
        description = request.form.get('description')
        input_format = request.form.get('inputFormat')
        expected_output = request.form.get('expectedOutput')
        
        # Validate required fields
        if not all([title, description, input_format, expected_output]):
            return jsonify({"error": "All fields are required"}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert the new challenge
        cursor.execute("""
            INSERT INTO coding_challenges 
            (title, description, input_format, expected_output, created_at) 
            VALUES (%s, %s, %s, %s, %s)
        """, (title, description, input_format, expected_output, datetime.datetime.now()))
        
        conn.commit()
        challenge_id = cursor.lastrowid
        
        return jsonify({
            "success": True,
            "message": "Challenge added successfully",
            "id": challenge_id
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/coding-challenges/<int:challenge_id>', methods=['DELETE'])
def delete_challenge(challenge_id):
    if 'loggedin' not in session or session.get('role') != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete related submissions first (to maintain referential integrity)
        cursor.execute("DELETE FROM coding_submissions WHERE challenge_id = %s", (challenge_id,))
        
        # Then delete the challenge
        cursor.execute("DELETE FROM coding_challenges WHERE id = %s", (challenge_id,))
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Challenge {challenge_id} deleted successfully"
        })
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/get_challenges')
def get_challenges_alias():
    return student_get_challenges()

# Student routes for coding challenges
@app.route('/get_challenges')
def student_get_challenges():
    if 'loggedin' not in session or session.get('role') != 'Student':
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, title, description, input_format
            FROM coding_challenges
            ORDER BY created_at DESC
        """)
        challenges = cursor.fetchall()
        
        return jsonify({"challenges": challenges})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Route to submit code (already exists)
@app.route('/submit_code', methods=['POST'])
def submit_code():
    if 'loggedin' not in session or session.get('role') != 'Student':
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        data = request.json
        user_id = session['id']
        challenge_id = data.get('challenge_id')
        code = data.get('code')
        input_data = data.get('input', '')
        language = data.get('language', 'python')  # Default to Python
        
        if not all([challenge_id, code]):
            return jsonify({"error": "Missing required fields"}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get expected output for evaluation
        cursor.execute("SELECT expected_output FROM coding_challenges WHERE id = %s", (challenge_id,))
        challenge = cursor.fetchone()
        
        if not challenge:
            return jsonify({"error": "Challenge not found"}), 404
        
        expected_output = challenge['expected_output']
        
        # Submit to Judge0
        language_id = LANGUAGE_IDS.get(language.lower())
        if not language_id:
            return jsonify({"error": f"Unsupported language: {language}"}), 400
        
        judge0_result = submit_to_judge0(code, language_id, input_data)
        
        # Check if output matches expected
        is_correct = False
        if judge0_result.get("status_id") == 3:  # If execution was successful
            user_output = judge0_result.get("stdout", "").strip()
            expected = expected_output.strip()
            is_correct = user_output == expected
        
        # Record submission in database
        status = "Correct" if is_correct else "Incorrect"
        if judge0_result.get("status_id") != 3:
            status = judge0_result.get("status", "Error")
            
        cursor.execute("""
            INSERT INTO coding_submissions 
            (user_id, challenge_id, submitted_code, input_data, output, expected_output, 
             submission_time, status, language)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id, challenge_id, code, input_data, 
            judge0_result.get("stdout", ""), expected_output,
            datetime.datetime.now(), status, language
        ))
        
        conn.commit()
        
        # Prepare response
        response_data = {
            "success": True,
            "status": judge0_result.get("status"),
            "output": judge0_result.get("stdout", ""),
            "is_correct": is_correct,
            "execution_time": f"{judge0_result.get('time', '0')} seconds",
            "memory_used": f"{judge0_result.get('memory', '0')} KB"
        }
        
        if judge0_result.get("stderr"):
            response_data["error_output"] = judge0_result.get("stderr")
        if judge0_result.get("compile_output"):
            response_data["compile_output"] = judge0_result.get("compile_output")
            
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin-ProgressDash')
def admin_pd():
    return render_template('AdminPD.html')

# Add this temporary route to app.py
@app.route('/test_judge0')
def test_judge0():
    test_code = """
print("Hello World")
"""
    result = submit_to_judge0(test_code, LANGUAGE_IDS['python'])
    return jsonify(result)

@app.route('/logout')
def logout():
    session.clear()  # Clear session for all user types
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))  # Redirect to the main page



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        conn = None
        cursor = None

        try:
            # Extract form data
            name = request.form.get('name')
            email = request.form.get('email')
            password_raw = request.form.get('password')
            role = request.form.get('role')

            # Debugging: Print received data
            print("\n--- Received Registration Data ---")
            print(json.dumps(request.form.to_dict(), indent=4))

            # Ensure required fields are present
            if not all([name, email, password_raw, role]):
                flash("All fields are required.", "danger")
                return redirect(url_for('register'))

            conn = get_db_connection()
            cursor = conn.cursor()

            # 🔹 **Check if the email is already registered**
            cursor.execute("SELECT * FROM Users WHERE Email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("This email is already registered. Please use a different email.", "danger")
                return redirect(url_for('register'))  # Show error on registration page

            # 🔹 **Encrypt the password**
            password = bcrypt.generate_password_hash(password_raw).decode('utf-8')

            # 🔹 **Insert into Users table**
            cursor.execute("INSERT INTO Users (Name, Email, Password, Role) VALUES (%s, %s, %s, %s)", 
                           (name, email, password, role))
            conn.commit()
            user_id = cursor.lastrowid  # Get the new UserID

            # 🔹 **Insert into role-specific tables**
            if role == "Student":
                batch_year = request.form.get('batch_year')
                if not batch_year:
                    flash("Batch year is required for students.", "danger")
                    return redirect(url_for('register'))
                cursor.execute("INSERT INTO Student (UserID, student_id, batch_year) VALUES (%s, %s, %s)", 
                               (user_id, user_id, batch_year))

            elif role == "Alumni":
                grad_year = request.form.get('grad_year')
                company = request.form.get('company', '')
                designation = request.form.get('designation', '')
                bio = request.form.get('bio', '')
                if not grad_year:
                    flash("Graduation year is required for alumni.", "danger")
                    return redirect(url_for('register'))
                cursor.execute("INSERT INTO Alumni (UserID, alumni_id, grad_year, company, designation, bio) VALUES (%s, %s, %s, %s, %s, %s)", 
                               (user_id, user_id, grad_year, company, designation, bio))

            elif role == "Admin":
                position = request.form.get('position')
                if not position:
                    flash("Position is required for admins.", "danger")
                    return redirect(url_for('register'))
                cursor.execute("INSERT INTO Admin (UserID, admin_id, position) VALUES (%s, %s, %s)", 
                               (user_id, user_id, position))

            conn.commit()
            flash("Registration successful!", "success")
            return redirect(url_for('home'))  # Redirect to home after successful registration

        except mysql.connector.Error as e:
            print("\n--- MySQL Error ---")
            print(str(e))  # Print error in console
            flash(f"MySQL Error: {str(e)}", "danger")

        except Exception as e:
            print("\n--- General Error ---")
            print(str(e))  # Print error in console
            flash(f"An error occurred: {str(e)}", "danger")

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('register.html')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

