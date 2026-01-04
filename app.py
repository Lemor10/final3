# app.py - Flask 3.x compatible
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, abort, jsonify ,session
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import date, datetime
import qrcode, io, csv, uuid
from io import BytesIO
from flask import g
import re
from itsdangerous import URLSafeTimedSerializer

if os.environ.get("RENDER"):
    BASE_URL = os.environ.get("BASE_URL")
    if not BASE_URL:
        raise RuntimeError("❌ BASE_URL is NOT set in Render environment variables")
else:
    BASE_URL = "http://localhost:5000"

app = Flask(__name__)

# ------------------ EMAIL CONFIG ------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # your email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # app password or SMTP password
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

app.config['DOG_UPLOAD_FOLDER'] = os.path.join('static', 'dog_images')
os.makedirs(app.config['DOG_UPLOAD_FOLDER'], exist_ok=True)

app.config['UPLOAD_FOLDER_PROFILE'] = os.path.join('static', 'profile_images')
os.makedirs(app.config['UPLOAD_FOLDER_PROFILE'], exist_ok=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'Dog_Registration_Secret_Key') # Detect if running on Render 
on_render = os.environ.get('RENDER') is not None 
if on_render: app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
else: app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://drs_user:kTr9P7RtYrfQkSt3C5IunMp6nw23x7f5@dpg-d5b4l6re5dus73feks6g-a.oregon-postgres.render.com/drs' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Persistent QR folder
QR_FOLDER = os.path.join('static', 'qr_dogs')
os.makedirs(QR_FOLDER, exist_ok=True)

# ------------------ Models ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    notifications = db.relationship(
    "Notification",
    backref="user",
    cascade="all, delete-orphan",
    passive_deletes=True
    )
    
    notifications = db.relationship(
        "Notification",
        backref="dog",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    email = db.Column(db.String(150), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(150))
    contact = db.Column(db.String(20))
    address = db.Column(db.String(255))
    profile_photo = db.Column(db.String(200))
    password_hash = db.Column(db.String(200), nullable=True)
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
    last_vaccination = db.Column(db.Date)
    next_vaccination = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False
    )

    dog_id = db.Column(
        db.Integer,
        db.ForeignKey("dog.id", ondelete="CASCADE"),
        nullable=True
    )

    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    due_date = db.Column(db.Date)
    is_read = db.Column(db.Boolean, default=False)
    dismissed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.id} - User {self.user_id} - Read {self.is_read}>"

def generate_vaccination_notifications(user_id):
    today = date.today()
    dogs = Dog.query.filter_by(owner_id=user_id).all()

    for dog in dogs:
        if not dog.next_vaccination:
            continue

        days_left = (dog.next_vaccination - today).days

        # Prevent duplicates
        existing = Notification.query.filter_by(
            user_id=user_id,
            dog_id=dog.id,
            due_date=dog.next_vaccination,
        ).first()

        if existing:
            continue

        if 0 <= days_left <= 7:
            notif = Notification(
                user_id=user_id,
                dog_id=dog.id,
                title="Vaccination Due Soon",
                message=f"{dog.name} needs vaccination in {days_left} days!",
                type="reminder",
                due_date=dog.next_vaccination
            )

        elif days_left < 0:
            notif = Notification(
                user_id=user_id,
                dog_id=dog.id,
                title="Vaccination Overdue",
                message=f"{dog.name}'s vaccination is overdue!",
                type="overdue",
                due_date=dog.next_vaccination
            )
        else:
            continue

        db.session.add(notif)

    db.session.commit()

def generate_admin_notifications(admin_user_id):
    """
    Generate notifications for admin:
    - New stray dogs registered
    - Vaccination reminder (7 days before)
    - Vaccination overdue for stray dogs
    """
    today = date.today()
    stray_dogs = Dog.query.filter(Dog.owner_id == None).all()  # Stray dogs

    for dog in stray_dogs:
        # Check if notification already exists for this dog and due_date
        exists = Notification.query.filter_by(
            user_id=admin_user_id,
            dog_id=dog.id,
            due_date=dog.next_vaccination if dog.next_vaccination else today
        ).first()
        if exists:
            continue

        # 1️⃣ New stray dog notification
        if not dog.next_vaccination:
            notif = Notification(
                user_id=admin_user_id,
                dog_id=dog.id,
                title="Stray Dog Alert",
                message=f"Stray dog '{dog.name}' is registered.",
                type="reminder",
                due_date=today
            )
            db.session.add(notif)
            continue  # No vaccination info, skip further checks

        # 2️⃣ Vaccination reminder (7 days before due)
        days_left = (dog.next_vaccination - today).days
        if 0 <= days_left <= 7:
            notif = Notification(
                user_id=admin_user_id,
                dog_id=dog.id,
                title="Stray Dog Vaccination Due Soon",
                message=f"'{dog.name}' needs vaccination in {days_left} days!",
                type="reminder",
                due_date=dog.next_vaccination
            )
            db.session.add(notif)

        # 3️⃣ Vaccination overdue
        elif days_left < 0:
            notif = Notification(
                user_id=admin_user_id,
                dog_id=dog.id,
                title="Stray Dog Vaccination Overdue",
                message=f"'{dog.name}' vaccination is overdue!",
                type="overdue",
                due_date=dog.next_vaccination
            )
            db.session.add(notif)

    db.session.commit()

def generate_email_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verify')

def confirm_email_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.loads(token, salt='email-verify', max_age=expiration)

def send_verification_email(user_email):
    # If running locally in debug mode, skip sending email
    if app.debug:
        print(f"⚠️ Debug mode: skipping email verification for {user_email}")
        # Auto-verify user for local development
        user = User.query.filter_by(email=user_email).first()
        if user:
            user.email_verified = True
            db.session.commit()
        return

    token = generate_email_token(user_email)
    verify_url = f"{BASE_URL}/verify_email/{token}"

    html = f"""
        <p>Hi!</p>
        <p>Click the link below to verify your email:</p>
        <a href="{verify_url}">Verify Email</a>
        <p>This link will expire in 1 hour.</p>
    """

    msg = Message(
        subject="Verify Your Email",
        recipients=[user_email],
        html=html,
        sender=app.config['MAIL_USERNAME']
    )

    mail.send(msg)
    print(f"✅ Verification email sent to {user_email}")

@app.route('/api/notification-count')
@login_required
def notification_count():
    count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False,
        dismissed=False
    ).count()
    return {"count": count}

@app.route('/owner/notifications')
@login_required
def owner_notifications():
    return render_template('owner_notifications.html')

# ------------------ Admin Notifications ------------------
@app.route('/admin/notifications')
@login_required
def admin_notifications():
    if current_user.role != 'admin':
        abort(403)

    # Generate notifications for admin before fetching
    admin = User.query.filter_by(role='admin').first()
    if admin:
        generate_admin_notifications(admin.id)

    # Fetch notifications
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        dismissed=False
    ).order_by(Notification.created_at.desc()).all()

    return render_template('admin_notifications.html', notifications=notifications)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    if notif.user_id != current_user.id:
        abort(403)

    notif.is_read = True
    db.session.commit()
    return {"success": True}

@app.route('/notifications/delete/<int:notif_id>', methods=['POST'])
@login_required
def delete_notification(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    if notif.user_id != current_user.id:
        abort(403)

    notif.dismissed = True     # ✅ change first
    db.session.commit()       # ✅ then commit

    return {"success": True}

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
@app.before_request
def load_notifications():
    if current_user.is_authenticated:
        if current_user.role == 'owner':
            generate_vaccination_notifications(current_user.id)
        elif current_user.role == 'admin':
            # Make sure the admin exists first
            admin = User.query.filter_by(role='admin').first()
            if admin:
                generate_admin_notifications(admin.id)
        g.notifications = Notification.query.filter_by(
            user_id=current_user.id,
            dismissed=False
        ).order_by(Notification.created_at.desc()).all()
    else:
        g.notifications = []

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
    dog = Dog.query.filter_by(uuid=dog_uuid).first()
    if not dog:
        abort(404)
    return render_template('dog_info.html', dog=dog)

def format_breed(breed):
    if not breed:
        return "Unknown"
    return breed.strip().lower().title()

# ------------------ Authentication ------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        contact = request.form['contact']
        address = request.form['address']
        password = request.form['password']
        confirm_password = request.form['confirm_password']  # 👈 ADD THIS

        # ✅ 1. Confirm password check (ADD HERE)
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        # ✅ 2. Optional: Password length validation
        if len(password) < 8 \
        or not re.search(r"[A-Z]", password) \
        or not re.search(r"[0-9]", password) \
        or not re.search(r"[^A-Za-z0-9]", password):
            flash(
                "Password must be at least 6 characters and include uppercase, number, and special character.",
                "error"
            )
            return redirect(url_for("signup"))

        # ✅ 3. Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('signup'))

        # ✅ 4. Create user only if all validations pass
        user = User(
            email=email,
            name=name,
            contact=contact,
            address=address,
            role='owner'
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        send_verification_email(user.email)  # ✅ send email

        flash("Verification email sent! Check your inbox.", "info")
        return redirect(url_for("login"))

    return render_template('signup.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    # 1️⃣ Confirm token
    email = confirm_email_token(token)
    if not email:
        flash("Verification link is invalid or has expired.", "danger")
        return redirect(url_for('signup'))

    # 2️⃣ Fetch the user
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('signup'))

    # 3️⃣ Check if already verified
    if user.email_verified:
        flash("Email already verified. You can log in.", "info")
        return redirect(url_for('login'))

    # 4️⃣ Mark as verified and save to DB
    user.email_verified = True
    db.session.commit()

    flash("Email verified successfully! You can now log in.", "success")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("This email is not registered.", "danger")
            return redirect(url_for('login'))

        if not user.check_password(password):
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for('login'))
        
        if not user.email_verified and user.role != 'admin':
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for("login"))

        login_user(user)

        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('owner_dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ------------------ Owner Dashboard ------------------
@app.route('/owner/dashboard')
@login_required
def owner_dashboard():
    dogs = Dog.query.filter_by(owner_id=current_user.id).all() if current_user.role=='owner' else Dog.query.all()

    alerts = []
    for dog in dogs:
        if dog.next_vaccination:
            days_left = (dog.next_vaccination - date.today()).days
            if days_left <= 7:  # 7 days before due
                alerts.append(f"{dog.name} needs vaccination in {days_left} days!")

    if current_user.role not in ['owner', 'admin']:
        abort(403)
    return render_template('owner_dashboard.html', dogs=dogs)

@app.route('/owner/profile', methods=['GET', 'POST'])
@login_required
def owner_profile():
    user = current_user
    dogs = Dog.query.filter_by(owner_id=user.id).all()

    if request.method == 'POST':
        # Check if this POST is for profile info or photo
        if 'name' in request.form:
            # Update profile info
            user.name = request.form.get('name')
            user.contact = request.form.get('contact')
            user.address = request.form.get('address')
            db.session.commit()
            flash("Profile updated successfully!", "success")
        elif 'profile_photo' in request.files:
            # Update profile photo
            photo = request.files['profile_photo']
            if photo.filename != '':
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename))
                user.profile_photo = filename
                db.session.commit()
                flash("Profile photo updated successfully!", "success")

        return redirect(url_for('owner_profile'))

    return render_template('owner_profile.html', dogs=dogs)


@app.route('/owner_add_dog', methods=['POST'])
@login_required
def owner_add_dog():
    name = request.form['name']
    breed = format_breed(request.form['breed'])
    age = int(request.form['age'])
    vaccinated = request.form['status']
    image = request.files.get("dog_image")

    # Read vaccination dates
    last_vaccination = request.form.get("last_vaccination")
    next_vaccination = request.form.get("next_vaccination")

    # Convert to date objects
    last_vac_date = datetime.strptime(last_vaccination, "%Y-%m-%d").date() if last_vaccination else None
    next_vac_date = datetime.strptime(next_vaccination, "%Y-%m-%d").date() if next_vaccination else None

    # Generate a unique UUID
    dog_uuid = str(uuid.uuid4())

    # Save dog image if uploaded
    if image and image.filename != '':
        filename = secure_filename(image.filename)
        DOG_IMAGE_FOLDER = os.path.join('static', 'dog_images')
        os.makedirs(DOG_IMAGE_FOLDER, exist_ok=True)
        image.save(os.path.join(DOG_IMAGE_FOLDER, filename))
    else:
        filename = None

    # Generate QR code pointing to dog's info page
    qr_data = url_for("dog_info", dog_uuid=dog_uuid, _external=True)
    img = qrcode.make(qr_data)
    qr_filename = f"{dog_uuid}.png"
    os.makedirs(QR_FOLDER, exist_ok=True)
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
        last_vaccination=last_vac_date,
        next_vaccination=next_vac_date,
        created_at=datetime.utcnow()
    )

    db.session.add(new_dog)
    db.session.commit()

    flash("Dog registered successfully! QR code generated.", "dog_success")
    return redirect(url_for('owner_profile'))

@app.route('/owner_delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def owner_delete_dog(dog_id):
    if current_user.role != 'owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
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
        return redirect(url_for('owner_profile'))

    dog.name = request.form['name']
    dog.breed = request.form['breed']
    dog.age = request.form['age']
    dog.vaccinated = request.form['status']

    last_vac = request.form.get('last_vaccination')
    next_vac = request.form.get('next_vaccination')
    dog.last_vaccination = datetime.strptime(last_vac, "%Y-%m-%d").date() if last_vac else None
    dog.next_vaccination = datetime.strptime(next_vac, "%Y-%m-%d").date() if next_vac else None

        # Optional image upload
    if 'dog_image' in request.files:
        file = request.files['dog_image']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['DOG_UPLOAD_FOLDER'], filename)
            file.save(file_path)
            dog.image = filename

    db.session.commit()
    flash("Dog information updated successfully!", "success")
    return redirect(url_for('owner_profile'))

# QR code serving
@app.route('/generate_qr/<dog_uuid>')
def generate_qr(dog_uuid):
    # Generate QR code for a dog
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5
    )

    qr.add_data(url_for("dog_info", dog_uuid=dog_uuid, _external=True))
  # Link encoded in QR
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

    if not dog.qr_code:
        abort(404, description="QR code not found")

    # Absolute path to file
    file_path = os.path.join(app.root_path, 'static', 'qr_dogs', dog.qr_code)

    if not os.path.exists(file_path):
        abort(404, description="QR file not found on server")

    return send_file(file_path, as_attachment=True)

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

    start_month = request.args.get("start_month")
    end_month = request.args.get("end_month")

    query = Dog.query
    if start_month and end_month:
        # Convert input to datetime
        start_date = datetime.strptime(start_month + "-01", "%Y-%m-%d")
        end_date = datetime.strptime(end_month + "-01", "%Y-%m-%d")
        # Get the last day of end month
        end_day = 28 if end_date.month == 2 else 30
        end_date = datetime(end_date.year, end_date.month, end_day, 23, 59, 59)
        query = query.filter(Dog.created_at >= start_date,
                             Dog.created_at <= end_date)

    dogs = query.all()

    # Summary
    total_owners = len(set(d.owner_id for d in dogs))
    total_dogs = len(dogs)

    # Bar chart (dogs per breed)
    breeds_list = [d.breed.capitalize() if d.breed else "Unknown" for d in dogs]
    breeds = list(set(breeds_list))
    breed_numbers = [breeds_list.count(b) for b in breeds]

    # Pie chart
    vaccinated_count = sum(1 for d in dogs if d.vaccinated == "Vaccinated")
    unvaccinated_count = sum(1 for d in dogs if d.vaccinated == "Not Vaccinated")

    # Line chart (monthly registrations)
    month_counts_dict = {}
    for d in dogs:
        m = d.created_at.strftime("%b %Y")
        month_counts_dict[m] = month_counts_dict.get(m, 0) + 1
    months = sorted(month_counts_dict.keys(), key=lambda x: datetime.strptime(x, "%b %Y"))
    month_counts = [month_counts_dict[m] for m in months]

    # If AJAX request, return JSON
    if request.args.get("ajax"):
        return jsonify({
            "total_owners": total_owners,
            "total_dogs": total_dogs,
            "breeds": breeds,
            "breed_numbers": breed_numbers,
            "vaccinated_count": vaccinated_count,
            "unvaccinated_count": unvaccinated_count,
            "months": months,
            "month_counts": month_counts
        })

    return render_template(
        'admin_data_analysis.html',
        total_owners=total_owners,
        total_dogs=total_dogs,
        breeds=breeds,
        breed_numbers=breed_numbers,
        vaccinated_count=vaccinated_count,
        unvaccinated_count=unvaccinated_count,
        months=months,
        month_counts=month_counts,
        start_month=start_month,
        end_month=end_month
    )

@app.route('/admin/register_dog', methods=['POST'])
@login_required
def admin_register_dog():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('admin_dashboard'))

    name = request.form['name']
    breed = format_breed(request.form['breed'])
    age = request.form['age']
    status = request.form['status']
    vaccinated = "Vaccinated" if status == "Vaccinated" else "Not Vaccinated"

    # Read vaccination dates
    last_vaccination = request.form.get("last_vaccination")
    next_vaccination = request.form.get("next_vaccination")

    # Convert to date objects
    last_vac_date = datetime.strptime(last_vaccination, "%Y-%m-%d").date() if last_vaccination else None
    next_vac_date = datetime.strptime(next_vaccination, "%Y-%m-%d").date() if next_vaccination else None

    image_file = request.files.get("dog_image")
    image_filename = None

    if image_file and image_file.filename != "":
        image_filename = secure_filename(image_file.filename)
        save_path = os.path.join("static/dog_images", image_filename)
        image_file.save(save_path)

    # Generate unique UUID
    dog_uuid = str(uuid.uuid4())

    # Generate QR code URL
    qr_data = url_for("dog_info", dog_uuid=dog_uuid, _external=True)

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
        image=image_filename,
        last_vaccination=last_vac_date,
        next_vaccination=next_vac_date,
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
    dog.last_vaccination = request.form.get('last_vaccination') or None
    dog.next_vaccination = request.form.get('next_vaccination') or None
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

@app.route('/admin/delete_owner/<int:owner_id>', methods=['POST'])
@login_required
def admin_delete_owner(owner_id):
    owner = User.query.get(owner_id)

    if not owner:
        flash("Owner not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Optional: delete owner's dogs as well
    dogs = Dog.query.filter_by(owner_id=owner_id).all()
    for dog in dogs:
        db.session.delete(dog)

    db.session.delete(owner)
    db.session.commit()

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
