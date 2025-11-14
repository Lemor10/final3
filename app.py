# app.py - Flask 3.x compatible
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import qrcode, io, csv
import uuid

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'Dog_Registration_Secret_Key')

# Detect if running on Render
on_render = os.environ.get('RENDER') is not None

if on_render:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://final3_a8kp_user:GvUqHBlfoAyUeWq5N5I5VTZ0e5EOZWg1@dpg-d40baa2li9vc73c4f0v0-a.oregon-postgres.render.com/final3_a8kp'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Ensure QR folder exists
QR_FOLDER = os.path.join('/tmp', 'qrcodes')
os.makedirs(QR_FOLDER, exist_ok=True)

# ------------------ Models ------------------
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
    vaccinated = db.Column(db.String(50), nullable=False, default="Not Vaccinated")
    image = db.Column(db.String(200))  # store image filename or URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ Ensure Admin Exists ------------------
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

# ------------------ Routes ------------------

# Welcome page
@app.route('/')
def index():
    return render_template('index.html')  # Clean welcome page without public dog view

# Scan QR page
@app.route('/scan')
def scan_qr():
    return render_template('scan.html')

# Dog info
@app.route('/dog/<string:dog_uuid>')
def dog_info(dog_uuid):
    dog = Dog.query.filter_by(uuid=dog_uuid).first_or_404()
    return render_template('dog_info.html', dog=dog)

# ------------------ Authentication ------------------
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
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        # Redirect based on role
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('owner_dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

# ------------------ Owner Dashboard ------------------
@app.route('/owner/dashboard')
@login_required
def owner_dashboard():
    if current_user.role not in ['owner', 'admin']:
        abort(403)
    dogs = Dog.query.filter_by(owner_id=current_user.id).all() if current_user.role=='owner' else Dog.query.all()
    return render_template('owner_dashboard.html', dogs=dogs)



# Owner register dog
@app.route('/owner/register_dog', methods=['GET','POST'])
@login_required
def register_dog():
    if request.method == 'POST':
        name = request.form['name']
        breed = request.form.get('breed')
        age = request.form.get('age') or 0
        owner_name = current_user.name or current_user.email
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

@app.route('/owner_add_dog', methods=['POST'])
@login_required
def owner_add_dog():
    name = request.form['name']
    breed = request.form['breed']
    age = request.form['age']
    vaccinated = request.form.get('status') == "Vaccinated"

    new_dog = Dog(
        uuid=str(uuid.uuid4()),   # 👈 THIS IS REQUIRED
        name=name,
        breed=breed,
        age=age,
        vaccinated=vaccinated,
        owner_id=current_user.id,
        owner_name=current_user.name,
        
        created_at=datetime.utcnow()
    )

    db.session.add(new_dog)
    db.session.commit()

    return redirect(url_for('owner_dashboard'))

@app.route('/owner_delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def owner_delete_dog(dog_id):
    if current_user.role != 'owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('signin'))
    
    dog = Dog.query.get_or_404(dog_id)
    
    # Make sure the logged-in owner owns this dog
    if dog.owner_id != current_user.id:
        flash('You can only delete your own dogs.', 'danger')
        return redirect(url_for('owner_dashboard'))
    
    db.session.delete(dog)
    db.session.commit()
    flash('Dog deleted successfully!', 'success')
    return redirect(url_for('owner_dashboard'))

@app.route('/owner/edit_dog/<int:dog_id>', methods=['POST'])
@login_required
def owner_edit_dog(dog_id):
    # Only owners can edit
    if current_user.role != 'owner':
        flash("Unauthorized access", "danger")
        return redirect(url_for('signin'))

    dog = Dog.query.get_or_404(dog_id)

    # Make sure the logged-in owner owns this dog
    if dog.owner_id != current_user.id:
        flash("You cannot edit this dog.", "danger")
        return redirect(url_for('owner_dashboard'))

    dog.name = request.form['name']
    dog.breed = request.form['breed']
    dog.age = request.form['age']
    dog.vaccinated = request.form['status']

    db.session.commit()
    flash("Dog information updated successfully!", "success")
    return redirect(url_for('owner_dashboard'))

# QR code serving
@app.route('/qrcodes/<path:filename>')
def qrcodes(filename):
    return send_from_directory(QR_FOLDER, filename)

@app.route('/download_qr/<string:dog_uuid>')
def download_qr(dog_uuid):
    dog = Dog.query.filter_by(uuid=dog_uuid).first_or_404()
    return send_from_directory(QR_FOLDER, dog.qr_code, as_attachment=True)

# ------------------ Admin Dashboard ------------------
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("You don't have permission to access this page.", "danger")
        return redirect(url_for('login'))

    users = User.query.filter_by(role='owner').all()  # Only show owners
    dogs = Dog.query.all()
    return render_template('admin_dashboard.html', users=users, dogs=dogs)

@app.route('/admin/data-analysis')
@login_required
def admin_data_analysis():
    if current_user.role != 'admin':
        abort(403)
    total_users = User.query.count()
    total_dogs = Dog.query.count()
    total_owners = User.query.filter_by(role='owner').count()
    total_admins = User.query.filter_by(role='admin').count()
    breed_counts = db.session.query(Dog.breed, db.func.count(Dog.id)).group_by(Dog.breed).all()
    breeds = [b[0] or "Unknown" for b in breed_counts]
    breed_numbers = [b[1] for b in breed_counts]
    return render_template('admin_data_analysis.html',
                           total_users=total_users,
                           total_dogs=total_dogs,
                           total_owners=total_owners,
                           total_admins=total_admins,
                           breeds=breeds,
                           breed_numbers=breed_numbers)

@app.route('/admin/register_dog', methods=['POST'])
def admin_register_dog():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('signin'))

    name = request.form['name']
    breed = request.form['breed']
    age = request.form['age']
    status = request.form['status']

    # Convert vaccinated status to boolean
    vaccinated = True if status == 'Vaccinated' else False

    new_dog = Dog(
        name=name,
        breed=breed,
        age=age,
        owner_name=None,   # because it's a stray
        owner_id=None,
        vaccinated=vaccinated
    )

    db.session.add(new_dog)
    db.session.commit()
    flash("Stray dog registered successfully!", "success")
    return redirect(url_for('admin_dashboard'))

# Export CSV
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

# Whoami for debug
@app.route('/whoami')
@login_required
def whoami():
    return f"Logged in as {current_user.email} with role {current_user.role}"

# ------------------ Run App ------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=True)
