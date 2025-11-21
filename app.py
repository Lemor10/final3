# app.py - Flask 3.x compatible
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import qrcode, io, csv
import uuid, qrcode
from io import BytesIO

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000') 
app = Flask(__name__) 
app.config['UPLOAD_FOLDER_PROFILE'] = os.path.join('static', 'profile_images')
os.makedirs(app.config['UPLOAD_FOLDER_PROFILE'], exist_ok=True)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'Dog_Registration_Secret_Key') # Detect if running on Render 
on_render = os.environ.get('RENDER') is not None 
if on_render: app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
else: app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://final3_a8kp_user:GvUqHBlfoAyUeWq5N5I5VTZ0e5EOZWg1@dpg-d40baa2li9vc73c4f0v0-a.oregon-postgres.render.com/final3_a8kp' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Persistent QR folder
QR_FOLDER = os.path.join('static', 'qr_dogs')
os.makedirs(QR_FOLDER, exist_ok=True)

# ------------------ Models ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150))
    contact = db.Column(db.String(20))
    address = db.Column(db.String(255))
    profile_photo = db.Column(db.String(200))
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
        contact = request.form['contact']
        address = request.form['address']
        profile_photo = request.form.get('profile_photo')
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

@app.route('/owner/profile', methods=['GET', 'POST'])
@login_required
def owner_profile():
    user = current_user
    dogs = Dog.query.filter_by(owner_id=user.id).all()  # 👈 Pass the owner’s dogs

    if request.method == 'POST':
        user.name = request.form['name']
        user.contact = request.form['contact']
        user.address = request.form['address']

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            photo = request.files['profile_photo']
            if photo.filename != '':
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename))
                user.profile_photo = filename

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('owner_profile'))

    return render_template('owner_profile.html', dogs=dogs)

@app.route('/owner_add_dog', methods=['POST'])
@login_required
def owner_add_dog():
    name = request.form['name']
    breed = request.form['breed']
    age = int(request.form['age'])
    vaccinated = request.form['status']
    image = request.files.get("dog_image")

    # Generate a unique UUID
    dog_uuid = str(uuid.uuid4())

    if image:
        filename = secure_filename(image.filename)
        image.save(os.path.join("static/dog_images", filename))
    else:
        filename = None

    # Generate QR code pointing to dog's info page
    qr_data = f"{request.url_root}dog/{dog_uuid}"
    img = qrcode.make(qr_data)
    qr_filename = f"{dog_uuid}.png"
    img.save(os.path.join(QR_FOLDER, qr_filename))

    # Create the dog entry
    new_dog = Dog(
        uuid=dog_uuid,
        name=name,
        breed=breed,
        age=age,
        vaccinated=vaccinated,
        owner_id=current_user.id,
        owner_name=current_user.name,
        qr_code=qr_filename,
        image=filename,
        created_at=datetime.utcnow()
    )

    db.session.add(new_dog)
    db.session.commit()

    flash("Dog registered successfully! QR code generated.", "success")
    return redirect(url_for('owner_profile'))


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
    return redirect(url_for('owner_profile'))

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
@app.route('/generate_qr/<dog_uuid>')
def generate_qr(dog_uuid):
    # Generate QR code for a dog
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5
    )
    qr.add_data(f'https://yourdomain.com/dog/{dog_uuid}')  # Link encoded in QR
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

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

    # Summary
    total_users = User.query.count()
    total_owners = User.query.filter_by(role='owner').count()
    total_dogs = Dog.query.count()

    # Bar Chart (Dogs per breed)
    breed_counts = (
        db.session.query(Dog.breed, db.func.count(Dog.id))
        .group_by(Dog.breed)
        .all()
    )
    breeds = [b[0] or "Unknown" for b in breed_counts]
    breed_numbers = [b[1] for b in breed_counts]

    # Pie Chart (Vaccinated vs Not)
    vaccinated_count = Dog.query.filter_by(vaccinated="Vaccinated").count()
    unvaccinated_count = Dog.query.filter_by(vaccinated="Not Vaccinated").count()

    # Line Chart (Monthly registrations)
    monthly_data = db.session.query(
        db.func.date_trunc('month', Dog.created_at),
        db.func.count(Dog.id)
    ).group_by(
        db.func.date_trunc('month', Dog.created_at)
    ).order_by(
        db.func.date_trunc('month', Dog.created_at)
    ).all()

    months = [m[0].strftime("%b %Y") for m in monthly_data]
    month_counts = [m[1] for m in monthly_data]

    return render_template(
        'admin_data_analysis.html',
        total_users=total_users,
        total_owners=total_owners,
        total_dogs=total_dogs,
        breeds=breeds,
        breed_numbers=breed_numbers,
        vaccinated_count=vaccinated_count,
        unvaccinated_count=unvaccinated_count,
        months=months,
        month_counts=month_counts
    )

@app.route('/admin/register_dog', methods=['POST'])
def admin_register_dog():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('admin_dashboard'))

    name = request.form['name']
    breed = request.form['breed']
    age = request.form['age']
    status = request.form['status']

    vaccinated = "Vaccinated" if status == "Vaccinated" else "Not Vaccinated"

    # Generate unique UUID
    dog_uuid = str(uuid.uuid4())

    # Generate QR code URL
    qr_data = f"{request.url_root}dog/{dog_uuid}"

    # Generate QR image
    img = qrcode.make(qr_data)

    # Save QR to /tmp/qrcodes
    qr_filename = f"{dog_uuid}.png"
    img.save(os.path.join(QR_FOLDER, qr_filename))

    # Save dog entry
    new_dog = Dog(
        uuid=dog_uuid,
        name=name,
        breed=breed,
        age=age,
        owner_name="Stray (Admin Registered)",
        owner_id=None,
        vaccinated=vaccinated,
        qr_code=qr_filename,
        created_at=datetime.utcnow()
    )

    db.session.add(new_dog)
    db.session.commit()

    flash("Stray dog registered successfully! QR code created.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_edit_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)

    dog.name = request.form['name']
    dog.breed = request.form['breed']
    dog.age = request.form['age']
    dog.vaccinated = request.form['status']

    db.session.commit()

    flash("Dog information updated successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_delete_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)

    # Delete QR if exists
    if dog.qr_code:
        try:
            os.remove(os.path.join(QR_FOLDER, dog.qr_code))
        except:
            pass

    db.session.delete(dog)
    db.session.commit()

    flash("Dog deleted successfully!", "success")
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
