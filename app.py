from flask import Flask, render_template, request, redirect, url_for, session, flash
from auth_module import SecureAuthModule
import os

app = Flask(__name__)
# Secret key is required for session management. In a real OS project, this would be injected via env variables.
app.secret_key = os.urandom(24) 

auth = SecureAuthModule()

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    success, message = auth.register_user(username, password)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    success, message = auth.authenticate_step_1(username, password)
    
    if success:
        session['mfa_pending_user'] = username
        return render_template('index.html', mfa_required=True, message=message)
    else:
        flash(message, 'error')
        return redirect(url_for('home'))

@app.route('/mfa', methods=['POST'])
def mfa():
    if 'mfa_pending_user' not in session:
        flash('Session expired or invalid. Try again.', 'error')
        return redirect(url_for('home'))
        
    username = session['mfa_pending_user']
    mfa_token = request.form.get('mfa_token')
    
    if auth.authenticate_step_2_mfa(username, mfa_token):
        del session['mfa_pending_user']
        session['user'] = username
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid MFA Token. Authentication Failed.', 'error')
        return render_template('index.html', mfa_required=True)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Unauthorized. Please log in.', 'error')
        return redirect(url_for('home'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('mfa_pending_user', None)
    flash('You have been securely logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Disable debug mode in production to prevent arbitrary code execution (trapdoor mitigation).
    app.run(debug=True, port=5000)
