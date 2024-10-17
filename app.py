import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Initialize Flask app
app = Flask(__name__)

# Configure the upload folder
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure PostgreSQL Database
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://umer404:Umer8637.@@localhost/extractmyinvoice"
app.config["SECRET_KEY"] = os.urandom(24)  # Generate a random secret key

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if not authenticated
login_manager.login_message_category = 'info'  # Set flash message category

# Allowed file extensions for images and documents
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}

class User(db.Model, UserMixin):  # UserMixin adds methods required by Flask-Login
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # Define relationship: one user can have many uploads
    uploads = db.relationship('Upload', backref='user', lazy=True)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    job_name = db.Column(db.String(200), nullable=False)
    file_format = db.Column(db.String(50), nullable=False)
    file_path = db.Column(db.String(300), nullable=False)

    # Foreign key to link the upload to the user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def Home():
    return render_template('home.html')

@app.route('/upload', methods=['POST', 'GET'])
@login_required  # Require login for uploading files
def upload():
    if request.method == 'POST':
        files = request.files.getlist('files[]')
        job_name = request.form.get('job_name')
        file_format = request.form.get('file_format')

        # Ensure there are files to upload
        if len(files) == 0:
            return jsonify({"error": "No files uploaded"}), 400

        # Validate the file format selection
        if not file_format:
            return jsonify({"error": "Please select a file format"}), 400

        uploaded_files = []

        # Process each file
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Save file details to the database, associate it with the logged-in user
                new_upload = Upload(
                    filename=filename,
                    job_name=job_name,
                    file_format=file_format,
                    file_path=file_path,
                    user_id=current_user.id  # Associate the upload with the current user
                )
                db.session.add(new_upload)
                db.session.commit()

                uploaded_files.append(filename)

        flash('Files uploaded successfully!', 'success')
        return redirect('upload')

    return render_template('upload.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash("Username or Email already taken", "danger")
            return redirect(url_for('register'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect('/login')

    return render_template('register.html')

# Define the login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/")  # Redirect to homepage if already logged in

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch the user by email
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # Log the user in
            
        flash('Login failed. Check your email or password', 'danger')  # Flash error message
        return redirect(url_for('login'))  # Redirect back to login

    return render_template('login.html')  # Render the login template

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log the user out
    flash('You have been logged out.', 'info')
    return redirect('/')

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
