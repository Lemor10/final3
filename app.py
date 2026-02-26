import os
import token
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, abort, jsonify ,session
#from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import date, datetime,timedelta
import qrcode, io, csv, uuid
from io import BytesIO
from flask import g
import re
from sqlalchemy import func, or_
from itsdangerous import URLSafeTimedSerializer
from flask import render_template_string
from dateutil.relativedelta import relativedelta
from openpyxl import Workbook
from docx import Document
from docx.shared import Inches
import matplotlib
matplotlib.use("Agg")  # VERY IMPORTANT
import matplotlib.pyplot as plt
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
import os

load_dotenv()

if os.environ.get("RENDER"):
    BASE_URL = os.environ.get("BASE_URL")
    if not BASE_URL:
        raise RuntimeError("❌ BASE_URL is NOT set in Render environment variables")
else:
    BASE_URL = "http://localhost:5000"

app = Flask(__name__)

app.config['DOG_UPLOAD_FOLDER'] = os.path.join('static', 'dog_images')
os.makedirs(app.config['DOG_UPLOAD_FOLDER'], exist_ok=True)

app.config['UPLOAD_FOLDER_PROFILE'] = os.path.join('static', 'profile_images')
os.makedirs(app.config['UPLOAD_FOLDER_PROFILE'], exist_ok=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'd1f4eb1ea051a0cf47ddb5be36e4d5e5f3073bb242b8ea7136bda03612b82c58')
on_render = os.environ.get('RENDER') is not None 
if on_render: app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
else: app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://drs_user:somepassword@localhost:5432/drs_local' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
print("SENDGRID KEY EXISTS:", bool(os.getenv("SENDGRID_API_KEY")))

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

QR_FOLDER = os.path.join('static', 'qr_dogs')
os.makedirs(QR_FOLDER, exist_ok=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    notifications = db.relationship(
    "Notification",
    backref="user",
    cascade="all, delete-orphan",
    passive_deletes=True
    )
    
    username = db.Column(db.String(50), unique=True, nullable=False)  
    email = db.Column(db.String(150), unique=True, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(200))
    last_notification_run = db.Column(db.Date)
    name = db.Column(db.String(150))
    contact = db.Column(db.String(20))
    barangay = db.Column(db.String(100))
    municipality = db.Column(db.String(100))
    province = db.Column(db.String(100))
    address = db.Column(db.String(255))
    profile_photo = db.Column(db.String(200))
    password_hash = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(20), default='owner')  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    dogs = db.relationship(
        'Dog',
        foreign_keys='Dog.owner_id',
        backref='owner',
        lazy=True
    )

    deleted_dogs = db.relationship(
        'Dog',
        foreign_keys='Dog.deleted_by_owner_id',
        lazy=True
    )
    is_archived = db.Column(db.Boolean, default=False)
    archived_at = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    deleted_reason = db.Column(db.String(100))
    deleted_cause = db.Column(db.String(150))
    deleted_at = db.Column(db.DateTime)
    deleted_by_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    archived_at = db.Column(db.DateTime)  # <-- ADD THIS
    name = db.Column(db.String(120), nullable=False)
    breed = db.Column(db.String(120))
    #age = db.Column(db.Integer)
    birthdate = db.Column(db.Date)  # New
    gender = db.Column(db.String(10))   # ✅ ADD THIS
    owner_name = db.Column(db.String(150))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    qr_code = db.Column(db.String(200))
    vaccinated = db.Column(db.String(50), nullable=False, default="Not Vaccinated")
    image = db.Column(db.String(200))  
    last_vaccination = db.Column(db.Date)
    next_vaccination = db.Column(db.Date)
    vaccination_expiry = db.Column(db.Date)  # ✅ NEW
    vaccination_barangay = db.Column(db.String(100))
    vaccination_municipality = db.Column(db.String(100))
    vaccination_province = db.Column(db.String(100))
    vaccination_location = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def age(self):
        if not self.birthdate:
            return "N/A"
        today = date.today()
        rd = relativedelta(today, self.birthdate)
        parts = []
        if rd.years > 0:
            parts.append(f"{rd.years} year{'s' if rd.years > 1 else ''}")
        if rd.months > 0:
            parts.append(f"{rd.months} month{'s' if rd.months > 1 else ''}")

        return " ".join(parts) if parts else "0 months"

class Notification(db.Model):
    __tablename__ = "notifications"

    __table_args__ = (
        db.UniqueConstraint(
            'user_id',
            'dog_id',
            'type',
            'milestone',
            name='unique_notification_per_dog_per_milestone'
        ),
    )

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
    milestone = db.Column(db.String(20))  # NEW: "7_days", "3_days", "1_day", "overdue"
    due_date = db.Column(db.Date)
    is_read = db.Column(db.Boolean, default=False)
    dismissed = db.Column(db.Boolean, default=False)
    email_sent = db.Column(db.Boolean, default=False)  # ✅ ADD THIS
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.id} - User {self.user_id} - Read {self.is_read}>"

def generate_vaccination_notifications(user_id, dog):
        today = date.today()
        if not dog.next_vaccination:
            return

        days_left = (dog.next_vaccination - today).days

        # Define milestones
        milestones = {
            7: "7_days",
            3: "3_days",
            1: "1_day",
            0: "overdue"
        }

        if days_left not in milestones:
            return
        
        milestone = milestones[days_left]

        # Prepare message
        if milestone == "overdue":
            title = "Vaccination Overdue"
            message = ( f"Dear {dog.owner_name},\n\n"
            f"Our records indicate that {dog.name}'s vaccination is overdue. "
            f"We strongly recommend that you schedule a visit with your veterinarian "
            f"as soon as possible to ensure {dog.name}'s continued health and wellbeing.\n\n"
            f"Thank you for your attention."
            )
            notif_type = "overdue"
        else:
            title = "Vaccination Due Soon"
            message = ( f"Dear {dog.owner_name},\n\n"
            f"This is a friendly reminder that {dog.name} is due for vaccination in {days_left} day{'s' if days_left > 1 else ''}. "
            f"Please schedule an appointment with your veterinarian to keep {dog.name} up-to-date with vaccinations.\n\n"
            f"Thank you for ensuring your pet’s health."
            )
            notif_type = "reminder"

        existing = Notification.query.filter_by(
            user_id=user_id,
            dog_id=dog.id,
            type=notif_type,    # ⚡ MUST include type
            milestone=milestone
        ).first()

        if existing:
            return
        
        notif = Notification(
            user_id=user_id,
            dog_id=dog.id,
            title=title,
            message=message,
            type=notif_type,
            milestone=milestone,
            due_date=dog.next_vaccination,
            email_sent=False
        )
        db.session.add(notif)
        db.session.flush()

        # Send email
        user = db.session.get(User, user_id)
        if user.email and not notif.email_sent:
            send_notification_email(to=user.email, subject=title, body=message)
            notif.email_sent = True

        db.session.commit()

def generate_admin_notifications(admin_user_id):
        today = date.today()
        dogs = Dog.query.filter_by(owner_id=None).all()

        for dog in dogs:
            if not dog.next_vaccination:
                continue

            # Owner-style milestones
            days_left = (dog.next_vaccination - today).days
            milestones = {7: "7_days", 3: "3_days", 1: "1_day", 0: "overdue"}

            if days_left not in milestones:
                continue

            milestone = milestones[days_left]

            existing = Notification.query.filter_by(
                user_id=admin_user_id,
                dog_id=dog.id,
                milestone=milestone
            ).first()

            if existing:
                continue

            if milestone == "overdue":
                title = "Stray Dog Vaccination Overdue"
                message = f"'{dog.name}' vaccination is overdue!"
                notif_type = "overdue"
            else:
                title = "Stray Dog Vaccination Due Soon"
                message = f"'{dog.name}' needs vaccination in {days_left} days!"
                notif_type = "reminder"

            existing = Notification.query.filter_by(
                    user_id=admin_user_id,
                    dog_id=dog.id,
                    type="stray_registered"
                ).first()
            if existing:
                continue

            notif = Notification(
                user_id=admin_user_id,
                dog_id=dog.id,
                title=title,
                message=message,
                type=notif_type,
                milestone=milestone,
                due_date=dog.next_vaccination,
                email_sent=False
            )
            db.session.add(notif)

        db.session.commit()

def send_notification_email(to, subject, body):
    message = Mail(
        from_email='TrackPawPH <dogrnw2026@gmail.com>',
        to_emails=to,
        subject=subject,
        html_content=f"<p>{body}</p>"
    )

    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print("Email sent:", response.status_code)
    except Exception as e:
        print("SendGrid error:", str(e))

def run_daily_notifications(user):
    today = date.today()

    if user.last_notification_run == today:
        return  # ❌ already ran today

    if user.role == "owner":
        generate_vaccination_notifications(user.id)

    elif user.role == "admin":
        generate_admin_notifications(user.id)

    user.last_notification_run = today
    db.session.commit()
    
def calculate_vaccination_expiry(last_vaccination):
    if not last_vaccination:
        return None
    return last_vaccination + timedelta(days=365)

def get_analysis_data(start_month=None, end_month=None):

    query = Dog.query.filter(Dog.is_archived == False)

    if start_month and end_month:
        start_date = datetime.strptime(start_month + "-01", "%Y-%m-%d")
        end_date = datetime.strptime(end_month + "-01", "%Y-%m-%d")
        end_day = 28 if end_date.month == 2 else 30
        end_date = datetime(end_date.year, end_date.month, end_day, 23, 59, 59)

        query = query.filter(
            Dog.created_at >= start_date,
            Dog.created_at <= end_date
        )

    dogs = query.all()

    # ---------------- DEATH ANALYTICS ----------------
    death_query = Dog.query.filter(
        Dog.deleted_by_owner_id.isnot(None),
        Dog.deleted_reason == "Death"
    )

    if start_month and end_month:
        death_query = death_query.filter(
            Dog.archived_at >= start_date,
            Dog.archived_at <= end_date
        )

    archived_dogs = death_query.all()
    total_deaths = len(archived_dogs)

    death_causes_list = [
        d.deleted_cause if d.deleted_cause else "Unknown"
        for d in archived_dogs
    ]

    death_causes = list(set(death_causes_list))
    death_counts = [death_causes_list.count(c) for c in death_causes]

    total_owners = len(set(d.owner_id for d in dogs))
    total_dogs = len(dogs)

    breeds_list = [d.breed.capitalize() if d.breed else "Unknown" for d in dogs]
    breeds = list(set(breeds_list))
    breed_numbers = [breeds_list.count(b) for b in breeds]

    vaccinated_count = sum(1 for d in dogs if d.vaccinated == "Vaccinated")
    unvaccinated_count = sum(1 for d in dogs if d.vaccinated == "Not Vaccinated")

    month_counts_dict = {}
    for d in dogs:
        m = d.created_at.strftime("%b %Y")
        month_counts_dict[m] = month_counts_dict.get(m, 0) + 1

    months = sorted(
        month_counts_dict.keys(),
        key=lambda x: datetime.strptime(x, "%b %Y")
    )
    month_counts = [month_counts_dict[m] for m in months]

    return {
        "total_owners": total_owners,
        "total_dogs": total_dogs,
        "breeds": breeds,
        "breed_numbers": breed_numbers,
        "vaccinated_count": vaccinated_count,
        "unvaccinated_count": unvaccinated_count,
        "months": months,
        "month_counts": month_counts,
        "total_deaths": total_deaths,
        "death_causes": death_causes,
        "death_counts": death_counts
    }

    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        return f"Status: {response.status_code}"
    except Exception as e:
        return str(e)
    
@app.route("/check-username")
def check_username():
    username = request.args.get("username", "").strip().lower()

    if not re.match(r"^[a-z0-9_]{4,20}$", username):
        return jsonify({
            "available": False,
            "message": "Invalid format (4–20 chars, letters/numbers/_ only)"
        })

    exists = User.query.filter(
        func.lower(User.username) == username
    ).first()

    if exists:
        return jsonify({
            "available": False,
            "message": "Username already taken"
        })

    return jsonify({
        "available": True,
        "message": "Username available"
    })

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
    Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False,
        dismissed=False
    ).update({Notification.is_read: True}, synchronize_session=False)
    db.session.commit()

    return render_template('owner_notifications.html')

# ------------------ Admin Notifications ------------------
@app.route('/admin/notifications')
@login_required
def admin_notifications():
    if current_user.role != 'admin':
        abort(403)

    generate_admin_notifications(current_user.id)

    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        dismissed=False
    ).order_by(Notification.created_at.desc()).all()

    unread_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False,
        dismissed=False
    ).count()

    return render_template(
        'admin_notifications.html',
        notifications=notifications,
        unread_count=unread_count
    )

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    if notif.user_id != current_user.id:
        abort(403)

    notif.is_read = True
    db.session.commit()
    return {"success": True}

@app.route("/notifications/cleanup", methods=["POST"])
@login_required
def cleanup_notifications():
    now = datetime.utcnow()

    # Delete read notifications older than 1 minute
    Notification.query.filter(
        Notification.is_read == True,
        Notification.created_at < now - timedelta(minutes=1)
    ).delete(synchronize_session=False)

    # Delete unread notifications older than 2 minutes
    Notification.query.filter(
        Notification.is_read == False,
        Notification.created_at < now - timedelta(minutes=2)
    ).update({Notification.dismissed: True}, synchronize_session=False)

    db.session.commit()
    return jsonify({"success": True})

with app.app_context():
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
#    admin = User.query.filter_by(email=admin_email).first()
##   if not admin:
#        admin = User(email=admin_email, name='Administrator', role='admin')
#        admin.set_password(admin_pass)
#       db.session.add(admin)
#        db.session.commit()
#        print(f"✅ Created admin: {admin_email}")

with app.app_context():
    User.query.filter(User.created_at == None)\
        .update({User.created_at: datetime.utcnow()})
    db.session.commit()

@app.before_request
def handle_notifications():
    if not current_user.is_authenticated:
        g.notifications = []
        return

    now = datetime.utcnow()

    # Clean up old notifications
    Notification.query.filter(
        Notification.is_read == True,
        Notification.created_at < now - timedelta(minutes=1)
    ).delete(synchronize_session=False)

    Notification.query.filter(
        Notification.is_read == False,
        Notification.created_at < now - timedelta(minutes=2)
    ).update({Notification.dismissed: True}, synchronize_session=False)
    db.session.commit()

    today = date.today()

    # Generate notifications once per day
    if current_user.last_notification_run != today:
        if current_user.role == "owner":
            dogs = Dog.query.filter_by(owner_id=current_user.id, is_archived=False).all()
            for dog in dogs:
                generate_vaccination_notifications(current_user.id, dog)
        elif current_user.role == 'admin':
            generate_admin_notifications(current_user.id)

        current_user.last_notification_run = today
        db.session.commit()

    # Load notifications for UI
    g.notifications = Notification.query.filter_by(
        user_id=current_user.id,
        dismissed=False
    ).order_by(Notification.created_at.desc()).all()
# ------------------ Routes ------------------

@app.route('/')
def index():
    return render_template('index.html') 

@app.route('/scan')
def scan_qr():
    return render_template('scan.html')

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

        province = request.form.get("province")
        municipality = request.form.get("municipality")
        barangay = request.form.get("barangay")

        full_address = f"{barangay}, {municipality}, {province}"

        form_data = {
            'email': request.form.get('email'),
            'name': request.form['name'],
            'username': request.form['username'].strip().lower(),
            'contact': request.form['contact'],
            'province': province,
            'municipality': municipality,
            'barangay': barangay
        }

        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            # Render the template directly, don't redirect
            return render_template(
                'signup.html',
                form_data=form_data,
                clear_passwords=True,   # flag to clear password fields
            )

        if len(password) < 8 \
        or not re.search(r"[A-Z]", password) \
        or not re.search(r"[a-z]", password) \
        or not re.search(r"[0-9]", password) \
        or not re.search(r"[^A-Za-z0-9]", password):
            flash(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
                "error"
            )
            return redirect(url_for("signup"))
        
        if form_data['username'] and User.query.filter_by(username=form_data['username']).first():
            flash('Username already taken.', 'error')
            form_data['username'] = ''       # 👈 CLEAR ONLY USERNAME
            return render_template('signup.html', form_data=form_data)
        
        if form_data['email'] and User.query.filter_by(email=form_data['email']).first():
            flash('Email already registered.', 'error')
            form_data['email'] = ''       # 👈 CLEAR ONLY EMAIL
            return render_template('signup.html', form_data=form_data)
        

        user = User(
            email=form_data['email'],
            name=form_data['name'],
            username=form_data['username'],
            contact=form_data['contact'],
            address=full_address,
            role='owner'
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        token = serializer.dumps(user.email, salt="email-verify")
        user.verification_token = token
        db.session.commit()

        # Use BASE_URL instead of url_for
        verify_link = f"{BASE_URL}/verify-email/{token}"

        html_template = f"""
        <p>Hello {user.name},</p>
        <p>Click below to verify your email:</p>
        <a href="{verify_link}">Verify Email</a>
        """

        message = Mail(
            from_email='TrackPawPH <dogrnw2026@gmail.com>',
            to_emails=user.email,
            subject="Verify Your Email",
            html_content=html_template
        )

        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print("Status Code:", response.status_code)
            print("Body:", response.body)
            print("Headers:", response.headers)

        except Exception as e:
            print("Verification email failed:", e)

        flash("Verification email sent. Please check your inbox.", "info")
        return redirect(url_for("login"))

    return render_template('signup.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt="email-verify", max_age=3600)
    except Exception:
        flash("Verification link expired.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Invalid verification link.", "danger")
        return redirect(url_for("login"))

    user.email_verified = True
    user.verification_token = None
    db.session.commit()

    flash("Email verified! You can now log in.", "success")
    return redirect(url_for("login"))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        email = request.form['email']

        user = User.query.filter_by(
            username=username,
            email=email
        ).first()

        if not user:
            flash("Username and email do not match.", "danger")
            return redirect(url_for('forgot_password'))

        token = serializer.dumps(user.id, salt='reset-password')

        return redirect(url_for('reset_password', token=token))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        user_id = serializer.loads(
            token,
            salt='reset-password',
            max_age=600  
        )
    except Exception:
        flash("Reset session expired or invalid. Try again.", "danger")
        return redirect(url_for('forgot_password'))

    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        if len(password) < 8 \
           or not re.search(r"[A-Z]", password) \
           or not re.search(r"[a-z]", password) \
           or not re.search(r"[0-9]", password) \
           or not re.search(r"[^A-Za-z0-9]", password):
            flash(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
                "danger"
            )
            return redirect(request.url)

        user.set_password(password)
        db.session.commit()

        flash("Password reset successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login').strip().lower() 
        password = request.form.get('password')

        user = User.query.filter(
            (func.lower(User.email) == login_input) |
            (func.lower(User.username) == login_input)
        ).first()

        if not user:
            flash("This email or username is not registered.", "danger")
            return redirect(url_for('login'))

        if not user.check_password(password):
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for('login'))
        
        # ✅ Only require email verification for owners
        if user.role == 'owner' and not user.email_verified:
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
    dogs = Dog.query.filter_by(owner_id=current_user.id, is_archived=False).all() if current_user.role=='owner' else Dog.query.all()
    
    stray_count = Dog.query.filter_by(owner_id=None).count()

    if current_user.role not in ['owner', 'admin']:
        abort(403)
    return render_template('owner_dashboard.html', dogs=dogs, stray_count=stray_count)

@app.route('/owner/profile', methods=['GET', 'POST'])
@login_required
def owner_profile():
    user = current_user
    dogs = Dog.query.filter_by(owner_id=user.id, is_archived=False).all()

    if request.method == 'POST':
        if 'name' in request.form:
            user.name = request.form.get('name')
            user.contact = request.form.get('contact')
            user.address = request.form.get('address')
            db.session.commit()
            flash("Profile updated successfully!", "success")
        elif 'profile_photo' in request.files:
            photo = request.files['profile_photo']
            if photo.filename != '':
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename))
                user.profile_photo = filename
                db.session.commit()
                flash("Profile photo updated successfully!", "success")

        return redirect(url_for('owner_profile'))

    return render_template('owner_profile.html', dogs=dogs)
from dateutil.relativedelta import relativedelta

@app.route('/owner_add_dog', methods=['POST'])
@login_required
def owner_add_dog():
    name = request.form['name']
    breed = format_breed(request.form['breed'])
    birthdate_str = request.form.get("birthdate")
    birthdate = datetime.strptime(birthdate_str, "%Y-%m-%d").date() if birthdate_str else None
    gender = request.form.get('gender')
    vaccinated = request.form['status']
    image = request.files.get("dog_image")

    last_vaccination = request.form.get("last_vaccination")
    next_vaccination = request.form.get("next_vaccination")

    last_vac_date = datetime.strptime(last_vaccination, "%Y-%m-%d").date() if last_vaccination else None
    next_vac_date = datetime.strptime(next_vaccination, "%Y-%m-%d").date() if next_vaccination else None

    if last_vac_date:
        # Vaccination expiry: 3 years after last vaccination
        vaccination_expiry = last_vac_date + relativedelta(years=3)

        # Next vaccination: if not entered, default to 1 year after last
        if not next_vac_date:
            next_vac_date = last_vac_date + relativedelta(years=1)
    else:
        next_vac_date = None
        vaccination_expiry = None
    
    vaccination_barangay = request.form.get("vaccination_barangay")
    vaccination_municipality = request.form.get("vaccination_municipality")
    vaccination_province = request.form.get("vaccination_province")
    vaccination_location = request.form.get("vaccination_location")

    dog_uuid = str(uuid.uuid4())

    if image and image.filename != '':
        filename = secure_filename(image.filename)
        DOG_IMAGE_FOLDER = os.path.join('static', 'dog_images')
        os.makedirs(DOG_IMAGE_FOLDER, exist_ok=True)
        image.save(os.path.join(DOG_IMAGE_FOLDER, filename))
    else:
        filename = None

    qr_data = url_for("dog_info", dog_uuid=dog_uuid, _external=True)
    img = qrcode.make(qr_data)
    qr_filename = f"{dog_uuid}.png"
    os.makedirs(QR_FOLDER, exist_ok=True)
    img.save(os.path.join(QR_FOLDER, qr_filename))

    new_dog = Dog(
        uuid=dog_uuid,
        name=name,
        breed=breed,
        birthdate=birthdate,
        gender=gender,
        vaccinated=vaccinated,
        owner_id=current_user.id,
        owner_name=current_user.name,
        qr_code=qr_filename,
        image=filename,
        last_vaccination=last_vac_date,
        next_vaccination=next_vac_date,
        vaccination_expiry=vaccination_expiry,
        vaccination_barangay=vaccination_barangay,
        vaccination_municipality=vaccination_municipality,
        vaccination_province=vaccination_province,
        vaccination_location=vaccination_location,
        created_at=datetime.utcnow(),
        is_archived=False  # ✅ Ensure new dogs are NOT archived
    )

    db.session.add(new_dog)
    db.session.commit()

    generate_vaccination_notifications(current_user.id, new_dog)

    flash("Dog registered successfully! QR code generated.", "dog_success")
    return redirect(url_for('owner_profile'))

@app.route('/owner_delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def owner_delete_dog(dog_id):

    # Role check
    if current_user.role != 'owner':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    dog = Dog.query.get_or_404(dog_id)

    # Ownership check
    if dog.owner_id != current_user.id:
        flash('You can only delete your own dogs.', 'danger')
        return redirect(url_for('owner_profile'))

    # Get form data
    delete_reason = request.form.get('delete_reason')
    delete_cause = request.form.get('delete_cause')

    # Validation
    if not delete_reason:
        flash('Deletion reason is required.', 'danger')
        return redirect(url_for('owner_profile'))

    # ARCHIVE instead of DELETE
    dog.is_archived = True
    dog.deleted_reason = delete_reason
    dog.deleted_cause = delete_cause if delete_reason == "Death" else None
    dog.deleted_at = datetime.utcnow()
    dog.archived_at = datetime.utcnow()  # ✅ unified timestamp
    dog.deleted_by_owner_id = current_user.id

    db.session.commit()

    flash('Dog record has been archived successfully.', 'success')
    return redirect(url_for('owner_profile'))

@app.route('/owner/edit_dog/<int:dog_id>', methods=['POST'])
@login_required
def owner_edit_dog(dog_id):
    if current_user.role != 'owner':
        flash("Unauthorized access", "danger")
        return redirect(url_for('signin'))

    dog = Dog.query.get_or_404(dog_id)

    if dog.owner_id != current_user.id:
        flash("You cannot edit this dog.", "danger")
        return redirect(url_for('owner_profile'))

    dog.name = request.form['name']
    dog.breed = request.form['breed']
    dog.gender = request.form['gender']
    birthdate_str = request.form.get("birthdate")
    dog.birthdate = datetime.strptime(birthdate_str, "%Y-%m-%d").date() if birthdate_str else None

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

@app.route('/generate_qr/<dog_uuid>')
def generate_qr(dog_uuid):
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5
    )

    qr.add_data(url_for("dog_info", dog_uuid=dog_uuid, _external=True))
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

    # Get current page from URL (?page=1)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 👈 change this to how many owners per page you want


    users_pagination = (
        User.query
        .filter_by(role='owner')
        .order_by(func.lower(User.name))   # ✅ ALPHABETICAL
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    users = users_pagination.items

    dogs = (
        Dog.query
        .filter(Dog.is_archived == False)
        .order_by(func.lower(Dog.name))    # ✅ ALPHABETICAL
        .all()
    )

    return render_template('admin_dashboard.html', users=users, dogs=dogs, pagination=users_pagination
)

@app.route('/admin/data-analysis')
@login_required
def admin_data_analysis():
    if current_user.role != 'admin':
        abort(403)

    start_month = request.args.get("start_month")
    end_month = request.args.get("end_month")

    data = get_analysis_data(start_month, end_month)

    query = Dog.query.filter(Dog.is_archived == False)
    if start_month and end_month:
        start_date = datetime.strptime(start_month + "-01", "%Y-%m-%d")
        end_date = datetime.strptime(end_month + "-01", "%Y-%m-%d")
        end_day = 28 if end_date.month == 2 else 30
        end_date = datetime(end_date.year, end_date.month, end_day, 23, 59, 59)
        query = query.filter(Dog.created_at >= start_date,
                             Dog.created_at <= end_date)

    dogs = query.all()

        # ---------------- DEATH ANALYTICS ----------------
    death_query = Dog.query.filter(
        Dog.deleted_by_owner_id.isnot(None),   # deleted by owner
        Dog.deleted_reason == "Death"          # reason = death
    )

    if start_month and end_month:
        death_query = death_query.filter(
            Dog.archived_at >= start_date,
            Dog.archived_at <= end_date
        )

    archived_dogs = death_query.all()

    total_deaths = len(archived_dogs)

    death_causes_list = [
        d.deleted_cause if d.deleted_cause else "Unknown"
        for d in archived_dogs
    ]

    death_causes = list(set(death_causes_list))
    death_counts = [death_causes_list.count(c) for c in death_causes]

    total_owners = len(set(d.owner_id for d in dogs))
    total_dogs = len(dogs)

    breeds_list = [d.breed.capitalize() if d.breed else "Unknown" for d in dogs]
    breeds = list(set(breeds_list))
    breed_numbers = [breeds_list.count(b) for b in breeds]

    vaccinated_count = sum(1 for d in dogs if d.vaccinated == "Vaccinated")
    unvaccinated_count = sum(1 for d in dogs if d.vaccinated == "Not Vaccinated")

    month_counts_dict = {}
    for d in dogs:
        m = d.created_at.strftime("%b %Y")
        month_counts_dict[m] = month_counts_dict.get(m, 0) + 1
    months = sorted(month_counts_dict.keys(), key=lambda x: datetime.strptime(x, "%b %Y"))
    month_counts = [month_counts_dict[m] for m in months]

    if request.args.get("ajax"):
        return jsonify(data)
    
    return render_template(
        'admin_data_analysis.html',
        **data,
        start_month=start_month,
        end_month=end_month
    )

@app.route("/admin/data-analysis/download")
@login_required
def download_data_analysis():

    if current_user.role != 'admin':
        abort(403)

    start_month = request.args.get("start_month")
    end_month = request.args.get("end_month")

    data = get_analysis_data(start_month, end_month)

    downloaded_at = datetime.utcnow()
    formatted_date = downloaded_at.strftime("%B %d, %Y")

    # Create Word document
    document = Document()
    document.add_heading("Dog Registration Data Analysis Report", level=1)
    document.add_paragraph(f"Data Analysis Report as of {formatted_date}")
    document.add_paragraph("")  # spacing

    document.add_paragraph(f"Total Owners: {data['total_owners']}")
    document.add_paragraph(f"Total Dogs: {data['total_dogs']}")
    document.add_paragraph(f"Total Deaths: {data['total_deaths']}")

    document.add_heading("Dogs per Breed", level=2)

    # ---------- BREED CHART ----------
    plt.figure()
    plt.bar(data["breeds"], data["breed_numbers"])
    plt.xticks(rotation=45)
    plt.title("Dogs per Breed")
    plt.tight_layout()

    breed_chart = io.BytesIO()
    plt.savefig(breed_chart, format="png")
    plt.close()
    breed_chart.seek(0)

    document.add_picture(breed_chart, width=Inches(5))

    # ---------- VACCINATION CHART ----------
    document.add_heading("Vaccination Status", level=2)

    plt.figure()
    plt.pie(
        [data["vaccinated_count"], data["unvaccinated_count"]],
        labels=["Vaccinated", "Not Vaccinated"],
        autopct="%1.1f%%"
    )
    plt.title("Vaccination Distribution")

    vac_chart = io.BytesIO()
    plt.savefig(vac_chart, format="png")
    plt.close()
    vac_chart.seek(0)

    document.add_picture(vac_chart, width=Inches(4))

    # ---------- MONTHLY REGISTRATION ----------
    document.add_heading("Monthly Registrations", level=2)

    plt.figure()
    plt.plot(data["months"], data["month_counts"], marker='o')
    plt.xticks(rotation=45)
    plt.title("Monthly Registrations")
    plt.tight_layout()

    month_chart = io.BytesIO()
    plt.savefig(month_chart, format="png")
    plt.close()
    month_chart.seek(0)

    document.add_picture(month_chart, width=Inches(5))

    # ---------- DEATH CAUSE ----------
    document.add_heading("Cause of Death", level=2)

    if data["death_causes"]:
        plt.figure()
        plt.bar(data["death_causes"], data["death_counts"])
        plt.xticks(rotation=45)
        plt.title("Cause of Death")
        plt.tight_layout()

        death_chart = io.BytesIO()
        plt.savefig(death_chart, format="png")
        plt.close()
        death_chart.seek(0)

        document.add_picture(death_chart, width=Inches(5))

    # Save file
    file_stream = io.BytesIO()
    document.save(file_stream)
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name="Dog_Data_Analysis_Report.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

@app.route('/admin/search-dogs')
@login_required
def admin_search_dogs():
    if current_user.role != 'admin':
        abort(403)

    query = request.args.get("q", "").strip().lower()
    search_field = request.args.get("search_field", "name")
    filter_status = request.args.get("filter", "all")

    dogs = Dog.query
                # Vaccination filter
    if filter_status in ["vaccinated", "not_vaccinated"]:
        status = "Vaccinated" if filter_status == "vaccinated" else "Not Vaccinated"
        dogs = dogs.filter(Dog.vaccinated == status)

    # Search by name, breed, owner
    if query:
            if search_field == "name":
                dogs = dogs.filter(Dog.name.ilike(f"%{query}%"))

            elif search_field == "breed":
                dogs = dogs.filter(Dog.breed.ilike(f"%{query}%"))

            elif search_field == "owner_name":
                dogs = dogs.filter(Dog.owner_name.ilike(f"%{query}%"))

            elif search_field == "gender":
                dogs = dogs.filter(func.lower(Dog.gender) == query.lower())

            elif search_field == "birthdate":
                try:
                    birthdate = date.fromisoformat(query)
                    dogs = dogs.filter(Dog.birthdate == birthdate)
                except ValueError:
                    dogs = dogs.filter(False)

        # ✅ FORCE ORIGINAL ORDER (IMPORTANT)
    dogs = dogs.order_by(Dog.created_at.desc()).all()

    # Render partial template for dog cards only
    return render_template("admin_dog_cards_partial.html", dogs=dogs)

@app.route('/admin/register_dog', methods=['POST'])
@login_required
def admin_register_dog():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('admin_dashboard'))

    name = request.form['name']
    breed = format_breed(request.form['breed'])
    birthdate_str = request.form.get("birthdate")
    birthdate = datetime.strptime(birthdate_str, "%Y-%m-%d").date() if birthdate_str else None
    gender = request.form.get("gender")
    status = request.form['status']
    vaccinated = "Vaccinated" if status == "Vaccinated" else "Not Vaccinated"

    last_vaccination = request.form.get("last_vaccination")
    next_vaccination = request.form.get("next_vaccination")

    last_vac_date = datetime.strptime(last_vaccination, "%Y-%m-%d").date() if last_vaccination else None
    next_vac_date = datetime.strptime(next_vaccination, "%Y-%m-%d").date() if next_vaccination else None

    if last_vac_date:
        # Expiry: 3 years after last vaccination
        vaccination_expiry = last_vac_date + relativedelta(years=3)

        # Next vaccination: 1 year after last if not provided
        if not next_vac_date:
            next_vac_date = last_vac_date + relativedelta(years=1)
    else:
        next_vac_date = None
        vaccination_expiry = None
    
    vaccination_barangay = request.form.get("vaccination_barangay")
    vaccination_municipality = request.form.get("vaccination_municipality") 
    vaccination_province = request.form.get("vaccination_province")
    vaccination_location = request.form.get("vaccination_location")

    image_file = request.files.get("dog_image")
    image_filename = None
    if image_file and image_file.filename != "":
        image_filename = secure_filename(image_file.filename)
        save_path = os.path.join("static/dog_images", image_filename)
        image_file.save(save_path)

    dog_uuid = str(uuid.uuid4())
    qr_data = url_for("dog_info", dog_uuid=dog_uuid, _external=True)
    img = qrcode.make(qr_data)
    qr_filename = f"{dog_uuid}.png"
    img.save(os.path.join(QR_FOLDER, qr_filename))

    new_dog = Dog(
        uuid=dog_uuid,
        name=name,
        breed=breed,
        birthdate=birthdate,
        gender=gender,
        owner_name="Stray (Admin Registered)",
        owner_id=None,
        vaccinated=vaccinated,
        qr_code=qr_filename,
        image=image_filename,
        last_vaccination=last_vac_date,
        next_vaccination=next_vac_date,
        vaccination_expiry=vaccination_expiry,  # ✅ NEW
        vaccination_barangay=vaccination_barangay,
        vaccination_municipality=vaccination_municipality,
        vaccination_province=vaccination_province,
        vaccination_location=vaccination_location,
        created_at=datetime.utcnow()
    )

    db.session.add(new_dog)
    db.session.commit()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_edit_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)

    dog.name = request.form['name']
    dog.breed = request.form['breed']
    dog.vaccinated = request.form['status']
    dog.last_vaccination = request.form.get('last_vaccination') or None
    dog.next_vaccination = request.form.get('next_vaccination') or None
    db.session.commit()

    flash("Dog information updated successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/archive-dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_archive_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)

    selected_reason = request.form.get("archive_reason_select")
    other_reason = request.form.get("archive_reason_other")

    if selected_reason == "Other":
        final_reason = other_reason
    else:
        final_reason = selected_reason

    dog.is_archived = True
    dog.archived_at = datetime.utcnow()
    dog.archive_reason = final_reason

    db.session.commit()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/archive')
@login_required
def admin_archive():
    if current_user.role != 'admin':
        abort(403)

    # Archived owners
    archived_owners = User.query.filter_by(is_archived=True).order_by(User.archived_at.desc()).all()

    # Archived dogs
    archived_dogs = Dog.query.filter_by(is_archived=True).order_by(Dog.archived_at.desc()).all()

    # Prepare extra info for template
    for dog in archived_dogs:
        # Owner info for display
        if dog.owner_id:
            dog.owner_name = dog.owner.name if dog.owner else "Unknown"
        else:
            dog.owner_name = "Stray"

        # Who archived
        if dog.deleted_by_owner_id:
            dog.archived_by = "Owner Deleted"
        else:
            dog.archived_by = "Admin Archived"

        # Reason / Cause display
        dog.deleted_reason = dog.deleted_reason or "N/A"
        dog.deleted_cause = dog.deleted_cause or ""

    return render_template(
        'admin_archive.html',
        archived_owners=archived_owners,
        archived_dogs=archived_dogs
    )

@app.route('/admin/permanent_delete_dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_permanent_delete_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)

    # 🧹 Delete QR file permanently
    if dog.qr_code:
        try:
            os.remove(os.path.join(QR_FOLDER, dog.qr_code))
        except FileNotFoundError:
            pass

    db.session.delete(dog)
    db.session.commit()

    return redirect(url_for('admin_archive'))

@app.route('/admin/restore_owner/<int:owner_id>', methods=['POST'])
@login_required
def admin_restore_owner(owner_id):
    if current_user.role != 'admin':
        abort(403)

    owner = User.query.get_or_404(owner_id)
    owner.is_archived = False
    owner.archived_at = None
    db.session.commit()

    flash(f"Owner '{owner.name}' has been restored.", "success")
    return redirect(url_for('admin_archive'))

@app.route('/admin/restore_dog/<int:dog_id>', methods=['POST'])
@login_required
def admin_restore_dog(dog_id):
    if current_user.role != 'admin':
        abort(403)

    dog = Dog.query.get_or_404(dog_id)
    dog.is_archived = False
    dog.archived_at = None
    dog.deleted_reason = None
    dog.deleted_cause = None
    dog.deleted_by_owner_id = None
    db.session.commit()

    return redirect(url_for('admin_archive'))

@app.route('/admin/delete_owner/<int:owner_id>', methods=['POST'])
@login_required
def admin_delete_owner(owner_id):
    owner = db.session.get(User, owner_id)
    if not owner:
        return redirect(url_for('admin_dashboard'))

    dogs = Dog.query.filter_by(owner_id=owner_id).all()
    for dog in dogs:
        db.session.delete(dog)

    db.session.delete(owner)
    db.session.commit()

    return redirect(url_for('admin_dashboard'))

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=True)
