import os
import datetime
import socket
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Prevent SMTP from hanging the entire server
socket.setdefaulttimeout(5.0)

app = Flask(__name__)

# --------------------------------------------------
# BASIC CONFIGURATION
# --------------------------------------------------

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'campusfix-super-secret-key-production')

# Use absolute path for SQLite on Linux servers
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'campus.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --------------------------------------------------
# GMAIL SMTP CONFIGURATION
# --------------------------------------------------

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'egajagadish@gmail.com')
raw_password = os.environ.get('MAIL_PASSWORD', 'foka kfvz ciqo vktz')
app.config['MAIL_PASSWORD'] = raw_password.replace(' ', '')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

db = SQLAlchemy(app)
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# --- Home Route ---
@app.route('/')
def home():
    return render_template('welcome.html')


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scholar_number = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='student')
    is_verified = db.Column(db.Boolean, default=False)


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(20), unique=True, nullable=False)
    scholar_number = db.Column(db.String(50), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    building = db.Column(db.String(100), nullable=False)
    room_no = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default='Pending')
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        scholar_num = request.form.get('scholar_number', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not scholar_num or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(scholar_number=scholar_num).first():
            flash('Scholar Number already registered.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email address already registered.', 'danger')
            return redirect(url_for('register'))

        hashed_pwd = generate_password_hash(password)

        user = User(
            scholar_number=scholar_num,
            email=email,
            password_hash=hashed_pwd,
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()

        email_sent = False
        try:
            token = serializer.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)

            msg = Message(
                subject='CampusFix - Verify Your Email',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email]
            )
            msg.body = f"""Hello,

Thank you for registering for CampusFix.

Please click the link below to verify your email address:
{confirm_url}

Regards,
CampusFix
"""
            mail.send(msg)
            email_sent = True
        except Exception as e:
            print("Render cloud blocked SMTP:", e)
            user.is_verified = True
            db.session.commit()

        if email_sent:
            flash('Verification link sent to your Gmail. Please check your inbox.', 'info')
        else:
            flash('Registration successful! You can now log in directly.', 'success')

        return redirect(url_for('login'))

    return render_template('login.html', action='register')


# --------------------------------------------------
# EMAIL VERIFICATION
# --------------------------------------------------

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('The verification link has expired.', 'danger')
        return redirect(url_for('login'))
    except BadSignature:
        flash('The verification link is invalid.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('Account not found.', 'danger')
        return redirect(url_for('login'))

    user.is_verified = True
    db.session.commit()

    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        scholar_num = request.form.get('scholar_number', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(scholar_number=scholar_num).first()

        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash('Please verify your email via Gmail first.', 'warning')
                return redirect(url_for('login'))

            session['user_id'] = user.id
            session['scholar_number'] = user.scholar_number
            session['role'] = user.role

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))

            return redirect(url_for('student_dashboard'))

        flash('Invalid Scholar Number or Password.', 'danger')

    return render_template('login.html', action='login')


# --------------------------------------------------
# ADMIN LOGIN
# --------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        scholar_num = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(scholar_number=scholar_num, role='admin').first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['scholar_number'] = user.scholar_number
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))

        flash('Invalid Admin ID or Password.', 'danger')

    return render_template('login.html')


# --------------------------------------------------
# STUDENT DASHBOARD
# --------------------------------------------------

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))

    try:
        my_tickets = Complaint.query.filter_by(
            scholar_number=session['scholar_number']
        ).order_by(Complaint.date_created.desc()).all()
    except Exception as e:
        print("Database query error:", e)
        my_tickets = []

    total_requests = len(my_tickets)
    resolved_count = sum(1 for t in my_tickets if t.status == 'Resolved')
    in_progress_count = sum(1 for t in my_tickets if t.status == 'In Progress')
    pending_count = sum(1 for t in my_tickets if t.status == 'Pending')

    return render_template(
        'student_dashboard.html',
        tickets=my_tickets,
        total_requests=total_requests,
        resolved_count=resolved_count,
        in_progress_count=in_progress_count,
        pending_count=pending_count
    )


# --------------------------------------------------
# REGISTER MAINTENANCE COMPLAINT
# --------------------------------------------------

@app.route('/student/register-complaint', methods=['GET', 'POST'], endpoint='register_complaint')
@app.route('/student/register-complaint-page', methods=['GET', 'POST'], endpoint='register_complaint_page')
@app.route('/student/register', methods=['GET', 'POST'])
def register_complaint():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('photo')
        filename = None

        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        count = Complaint.query.count() + 1
        ticket_id = f"CMP{count:03d}"

        new_complaint = Complaint(
            ticket_id=ticket_id,
            scholar_number=session['scholar_number'],
            student_name=request.form.get('student_name', ''),
            department=request.form.get('department', ''),
            building=request.form.get('building', ''),
            room_no=request.form.get('room_no', ''),
            category=request.form.get('category', ''),
            priority=request.form.get('priority', 'Medium'),
            description=request.form.get('description', ''),
            photo_filename=filename
        )

        db.session.add(new_complaint)
        db.session.commit()

        flash(f'Complaint Registered Successfully! Ticket ID: {ticket_id}', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('register_complaint.html')


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    all_tickets = Complaint.query.order_by(Complaint.date_created.desc()).all()

    total_count = len(all_tickets)
    resolved_count = sum(1 for t in all_tickets if t.status == 'Resolved')
    progress_count = sum(1 for t in all_tickets if t.status == 'In Progress')
    pending_count = sum(1 for t in all_tickets if t.status == 'Pending')

    category_counts = {}
    for ticket in all_tickets:
        category = ticket.category
        category_counts[category] = category_counts.get(category, 0) + 1

    category_labels = list(category_counts.keys())
    category_values = list(category_counts.values())
    common_category = max(category_counts, key=category_counts.get) if category_counts else 'No complaints yet'

    today = datetime.datetime.now().date()
    trend_labels = []
    trend_values = []

    for i in range(6, -1, -1):
        current_date = today - datetime.timedelta(days=i)
        trend_labels.append(current_date.strftime('%b %d'))
        count = sum(
            1 for t in all_tickets
            if t.status == 'Resolved' and t.date_created and t.date_created.date() == current_date
        )
        trend_values.append(count)

    time_labels = category_labels
    time_values = [
        sum(1 for t in all_tickets if t.category == category and t.status == 'Resolved')
        for category in category_labels
    ]

    time_colors = ['#4285F4', '#45C98A', '#FFB526', '#9B59E8', '#EF5B70', '#28B9D4']

    return render_template(
        'admin_dashboard.html',
        tickets=all_tickets,
        total_count=total_count,
        resolved_count=resolved_count,
        progress_count=progress_count,
        pending_count=pending_count,
        category_labels=category_labels,
        category_values=category_values,
        trend_labels=trend_labels,
        trend_values=trend_values,
        time_labels=time_labels,
        time_values=time_values,
        time_colors=time_colors,
        fastest_resolution='Not available',
        common_category=common_category,
        average_resolution='Not available'
    )


# --------------------------------------------------
# UPDATE COMPLAINT STATUS
# --------------------------------------------------

@app.route('/admin/update_status/<int:ticket_id>', methods=['POST'])
def update_status(ticket_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    ticket = Complaint.query.get_or_404(ticket_id)
    ticket.status = request.form.get('status', 'Pending')
    db.session.commit()

    flash(f'Status updated for {ticket.ticket_id}', 'info')
    return redirect(url_for('admin_dashboard'))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --------------------------------------------------
# PRODUCTION DB INITIALIZATION & RUN
# --------------------------------------------------

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)