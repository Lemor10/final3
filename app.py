# app.py - Flask 3.x compatible
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode, io, csv

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'Dog_Registration_Secret_Key')

# Detect if running on Render (Render sets this environment variable automatically)
on_render = os.environ.get('RENDER') is not None

if on_render:
    # Use Render PostgreSQL45\
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
else:
    # Use local SQLite for development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://final3_a8kp_user:GvUqHBlfoAyUeWq5N5I5VTZ0e5EOZWg1@dpg-d40baa2li9vc73c4f0v0-a.oregon-postgres.render.com/final3_a8kp'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ensure QR folder exists
QR_FOLDER = os.path.join('/tmp', 'qrcodes')
os.makedirs(QR_FOLDER, exist_ok=True)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150))
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='owner')  # 'owner' or 'admin'
    dogs = db.relationship('Dog', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    breed = db.Column(db.String(120))
    age = db.Column(db.Integer)
    owner_name = db.Column(db.String(150))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    qr_code = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(email=admin_email, name='Administrator', role='admin')
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Created admin: {admin_email}")

# Routes
@app.route('/scan')
def scan_qr():
    return render_template('scan.html')

@app.route('/')
def index():
    dogs = Dog.query.all()
    return render_template('index.html', dogs=dogs)

@app.route('/dog/<string:dog_uuid>')
def dog_info(dog_uuid):
    dog = Dog.query.filter_by(uuid=dog_uuid).first()
    return render_template('dog_info.html', dog=dog)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))
        user = User(email=email, name=name, role='owner')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        # Check if user exists and password matches
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        # Log in user
        login_user(user)

        # Debug (optional)
        print(f"✅ Login successful: {user.email} | Role: {user.role}")

        # Redirect based on role
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('owner_dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/owner/dashboard')
@login_required
def owner_dashboard():
    if current_user.role != 'owner' and current_user.role != 'admin':
        abort(403)
    dogs = Dog.query.filter_by(owner_id=current_user.id).all() if current_user.role=='owner' else Dog.query.all()
    return render_template('owner_dashboard.html', dogs=dogs)

@app.route('/owner/register_dog', methods=['GET','POST'])
@login_required
def register_dog():
    if request.method == 'POST':
        name = request.form['name']
        breed = request.form.get('breed')
        age = request.form.get('age') or 0
        owner_name = current_user.name or request.form.get('owner_name') or current_user.email
        dog_uuid = os.urandom(16).hex()
        qr_data = f"{request.url_root}/dog/{dog_uuid}"
        img = qrcode.make(qr_data)
        qr_filename = f"{dog_uuid}.png"
        img.save(os.path.join(QR_FOLDER, qr_filename))
        dog = Dog(uuid=dog_uuid, name=name, breed=breed, age=int(age), owner_name=owner_name, owner_id=current_user.id, qr_code=qr_filename)
        db.session.add(dog)
        db.session.commit()
        flash('Dog registered successfully', 'success')
        return redirect(url_for('owner_dashboard'))
    return render_template('register.html')

@app.route('/qrcodes/<path:filename>')
def qrcodes(filename):
    return send_from_directory(QR_FOLDER, filename)

@app.route('/download_qr/<string:dog_uuid>')
def download_qr(dog_uuid):
    dog = Dog.query.filter_by(uuid=dog_uuid).first_or_404()
    return send_from_directory(QR_FOLDER, dog.qr_code, as_attachment=True)

@app.route('/admin')
@login_required
def admin_dashboard():
    # Ensure only admins can access
    if current_user.role != 'admin':
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('login'))

    users = User.query.all()
    dogs = Dog.query.all()

    # Debug
    print(f"DEBUG: {current_user.email} | {current_user.role}")

    return render_template('admin_dashboard.html', users=users, dogs=dogs)

@app.route('/admin/export_csv')
@login_required
def export_csv():
    if current_user.role != 'admin':
        abort(403)
    dogs = Dog.query.all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['id','uuid','name','breed','age','owner_name','owner_email'])
    for d in dogs:
        writer.writerow([d.id, d.uuid, d.name, d.breed, d.age, d.owner_name, d.owner.email if d.owner else ''])
    output = io.BytesIO(si.getvalue().encode())
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='dogs.csv')

@app.route('/whoami')
@login_required
def whoami():
    return f"Logged in as {current_user.email} with role {current_user.role}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=True)
