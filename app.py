import re

from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import nltk
from nltk.tokenize import word_tokenize, RegexpTokenizer
import subprocess

# nltk.download("maxent_ne_chunker",download_dir='/content/nltk_data/')
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    username = session.get('username')
    return render_template('index.html', username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        session['username'] = username
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Account already exists. Please choose a different username.', 'error')
            return render_template('signup.html')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


command_mapping = {
    'cd': ('change', 'directory'),
    'touch': ('create', 'file'),
    'cat': ('read', 'file'),
    'ls': ('list', 'files'),
    'rm': ('remove', 'file'),
    'pwd': ('directory','information'),
    'mkdir': ('make','directory'),
    'rename': ('rename','file'),
    'echo': ('print','text'),
    'echo': ('print','sentence'),
    'echo': ('print','line'),
    # Add more commands and their associated verb-entity pairs as needed
}


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def execute_cd(command):
    try:
        os.chdir(command[3:].strip())
        return jsonify({"result": f"Changed directory to: {os.getcwd()}"})
    except Exception as e:
        return make_response(jsonify({"error": f"Error changing directory: {str(e)}"}), 500)


def execute_cat(command):
    filename = command[4:].strip()
    try:
        with open(filename, 'r') as file:
            content = file.read()
        return jsonify({"result": content})
    except Exception as e:
        return make_response(jsonify({"error": f"Error reading file: {str(e)}"}), 500)


def execute_touch(command):
    filename = command[6:].strip()
    try:
        with open(filename, 'w'):
            pass  # This creates an empty file
        result = f"File '{filename}' created successfully."
    except Exception as e:
        return make_response(jsonify({"error": f"Error creating file: {str(e)}"}), 500)
    return jsonify({"result": result})


def execute_echo(command):
    parts = command.split(' ')
    if len(parts) >= 3 and parts[1] == '>>':
        filename = parts[2]
        message = ' '.join(parts[3:]).strip()
        try:
            with open(filename, 'a') as file:
                file.write(message + '\n')
            result = f"Appended message to '{filename}'."
        except Exception as e:
            return make_response(jsonify({"error": f"Error appending to file: {str(e)}"}), 500)
    else:
        message = command[5:].strip()
    return jsonify({"result": message})


def execute_write(command):
    parts = command.split(' ')
    if len(parts) >= 3:
        filename = parts[1]
        content = ' '.join(parts[2:]).strip()
        try:
            with open(filename, 'w') as file:
                file.write(content)
            result = f"Content written to '{filename}' successfully."
            return jsonify({"result": result})
        except Exception as e:
            return make_response(jsonify({"error": f"Error writing to file: {str(e)}"}), 500)
    else:
        return jsonify({"result": "Invalid command format. Usage: write <filename> <content>"})


def execute_pwd():
    try:
        current_directory = os.getcwd()
        return jsonify({"result": current_directory})
    except Exception as e:
        return make_response(jsonify({"error": f"Error getting current directory: {str(e)}"}), 500)


def execute_rename(command):
    parts = command.split(' ')
    if len(parts) == 3:
        old_filename = parts[1]
        new_filename = parts[2]
        try:
            os.rename(old_filename, new_filename)
            result = f"File '{old_filename}' renamed to '{new_filename}' successfully."
            return jsonify({"result": result})
        except Exception as e:
            return make_response(jsonify({"error": f"Error renaming file: {str(e)}"}), 500)
    else:
        return jsonify({"result": "Invalid command format. Usage: rename <old_filename> <new_filename>"})


def execute_mkdir(command):
    directory_name = command[6:].strip()
    try:
        os.mkdir(directory_name)
        result = f"Created directory: {directory_name}"
    except Exception as e:
        return make_response(jsonify({"error": f"Error creating directory: {str(e)}"}), 500)
    return jsonify({"result": result})


def execute_rm(command):
    file_name = command[3:].strip()
    try:
        os.remove(file_name)
        result = f"Removed file: {file_name}"
    except Exception as e:
        return make_response(jsonify({"error": f"Error removing file: {str(e)}"}), 500)
    return jsonify({"result": result})


def process_command_nltk(command):
    tokens = nltk.word_tokenize(command)  # Tokenize the sentence into words

    # Look for multi-word expressions (phrases)
    tagged = nltk.pos_tag(tokens, tagset='universal')
    expressions = []
    current_expression = []
    print(tagged)
    for word, tag in tagged:
        if tag.startswith('N') or tag.startswith('V'):  # Consider nouns and verbs
            expressions.append(word)
        else:
            if len(current_expression) >= 1:
                expressions.append(' '.join(current_expression))
            current_expression = []
    print(expressions)

    return expressions
def extract_strings_within_quotes(input_string):
    # Use regular expression to find strings within double quotes
    matches = re.findall(r'"([^"]*)"', input_string)

    # Concatenate the extracted strings into a single string
    extracted_string = ' '.join(matches)

    return extracted_string

@app.route('/execute_command', methods=['POST'])
def execute_command():
    command = request.form.get('command').strip()

    if command.startswith('cd '):
        return execute_cd(command)

    elif command.startswith('touch '):
        return execute_touch(command)

    elif command.startswith('echo '):
        return execute_echo(command)

    elif command.startswith('pwd'):
        return execute_pwd()

    elif command.startswith('mkdir '):
        return execute_mkdir(command)

    elif command.startswith('rm '):
        return execute_rm(command)

    elif command.startswith('cat '):
        return execute_cat(command)
    elif command.startswith('write '):
        return execute_write(command)

    elif command.startswith('rename '):
        return execute_rename(command)

    elif command == 'ls':
        try:
            result = subprocess.check_output(['ls'], stderr=subprocess.STDOUT, universal_newlines=True)
            return jsonify({"result": result})
        except subprocess.CalledProcessError as e:
            return make_response(jsonify({"error": f"Error executing 'ls' command: {e.output}"}), 500)
    else:
        result = process_command_nltk(command)
        main_verb = result[0].lower()
        object_entity = result[1].lower()
        path = ""
        if (len(result) > 2):
            path = result[len(result) - 1]
        print(main_verb + " " + path)

        # Match the identified components to terminal-like commands
        matched_command = None
        for cmd, (verb, entity) in command_mapping.items():
            if main_verb == verb and object_entity == entity:
                matched_command = cmd
                break
        if matched_command.startswith('rename'):
            matched_command+=' '+result[len(result)-2]
        elif matched_command.startswith('echo'):
            matched_command+=' '+extract_strings_within_quotes(command)
        elif path!= "":
            matched_command += ' '+path
        print(matched_command)
        if matched_command.startswith('cd '):
            return execute_cd(matched_command)

        elif matched_command.startswith('touch '):
            return execute_touch(matched_command)

        elif matched_command.startswith('echo '):
            return execute_echo(matched_command)

        elif matched_command.startswith('pwd'):
            return execute_pwd()

        elif matched_command.startswith('mkdir '):
            return execute_mkdir(matched_command)

        elif matched_command.startswith('rm '):
            return execute_rm(matched_command)

        elif matched_command.startswith('cat '):
            return execute_cat(matched_command)
        elif matched_command.startswith('write '):
            return execute_write(matched_command)

        elif matched_command.startswith('rename '):
            return execute_rename(matched_command)

        elif matched_command == 'ls':
            try:
                result = subprocess.check_output(['ls'], stderr=subprocess.STDOUT, universal_newlines=True)
                return jsonify({"result": result})
            except subprocess.CalledProcessError as e:
                return make_response(jsonify({"error": f"Error executing 'ls' command: {e.output}"}), 500)
        return jsonify({"result": "NLP used"})

    return jsonify({"result": "Command not supported"})


with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True, port=5001)
