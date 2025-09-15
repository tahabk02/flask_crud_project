from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_migrate import Migrate
from datetime import datetime, timezone
import os
import time
from werkzeug.utils import secure_filename
import re
import logging
from functools import wraps

# =============== CONFIGURATION ===============

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "info"

# Logging configuration
if not app.debug:
    logging.basicConfig(level=logging.INFO)

# =============== FORMS ===============

class ContactForm(FlaskForm):
    name = StringField('Nom', validators=[
        DataRequired(message='Le nom est requis'), 
        Length(min=2, max=100, message='Le nom doit contenir entre 2 et 100 caractères')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='L\'email est requis'), 
        Email(message='Veuillez entrer un email valide')
    ])
    subject = StringField('Sujet', validators=[
        DataRequired(message='Le sujet est requis'),
        Length(min=5, max=200, message='Le sujet doit contenir entre 5 et 200 caractères')
    ])
    message = TextAreaField('Message', validators=[
        DataRequired(message='Le message est requis'),
        Length(min=10, max=1000, message='Le message doit contenir entre 10 et 1000 caractères')
    ])
    submit = SubmitField('Envoyer le message')

class LoginForm(FlaskForm):
    username = StringField('Email ou nom d\'utilisateur', validators=[
        DataRequired(message='Ce champ est requis')
    ])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(message='Le mot de passe est requis')
    ])
    remember_me = BooleanField('Se souvenir de moi')
    submit = SubmitField('Se connecter')

class SignupForm(FlaskForm):
    name = StringField('Nom complet', validators=[
        DataRequired(message='Le nom est requis'),
        Length(min=2, max=100, message='Le nom doit contenir entre 2 et 100 caractères')
    ])
    email = StringField('Adresse email', validators=[
        DataRequired(message='L\'email est requis'),
        Email(message='Veuillez entrer un email valide')
    ])
    phone = StringField('Téléphone', validators=[
        Length(max=20, message='Le numéro ne peut pas dépasser 20 caractères')
    ])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(message='Le mot de passe est requis'),
        Length(min=8, message='Le mot de passe doit contenir au moins 8 caractères')
    ])
    confirm_password = PasswordField('Confirmer le mot de passe', validators=[
        DataRequired(message='Veuillez confirmer le mot de passe'),
        EqualTo('password', message='Les mots de passe ne correspondent pas')
    ])
    terms = BooleanField('J\'accepte les conditions d\'utilisation', validators=[
        DataRequired(message='Vous devez accepter les conditions')
    ])
    submit = SubmitField('Créer le compte')

class CreateUserForm(FlaskForm):
    name = StringField('Nom complet', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Adresse email', validators=[DataRequired(), Email()])
    phone = StringField('Téléphone', validators=[Length(max=20)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=8)])
    status = SelectField('Statut', choices=[
        ('active', 'Actif'), 
        ('pending', 'En attente'), 
        ('inactive', 'Inactif'), 
        ('suspended', 'Suspendu')
    ], default='active')
    submit = SubmitField('Créer l\'utilisateur')

class UpdateUserForm(FlaskForm):
    name = StringField('Nom complet', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Adresse email', validators=[DataRequired(), Email()])
    phone = StringField('Téléphone', validators=[Length(max=20)])
    password = PasswordField('Nouveau mot de passe (optionnel)', validators=[Length(min=8)])
    status = SelectField('Statut', choices=[
        ('active', 'Actif'), 
        ('pending', 'En attente'), 
        ('inactive', 'Inactif'), 
        ('suspended', 'Suspendu')
    ])
    submit = SubmitField('Modifier l\'utilisateur')

class TaskForm(FlaskForm):
    title = StringField('Titre', validators=[
        DataRequired(message='Le titre est requis'),
        Length(max=200, message='Le titre ne peut pas dépasser 200 caractères')
    ])
    description = TextAreaField('Description', validators=[
        Length(max=5000, message='La description ne peut pas dépasser 5000 caractères')
    ])
    status = SelectField('Statut', choices=[
        ('pending', 'En attente'), 
        ('in_progress', 'En cours'), 
        ('completed', 'Terminé')
    ], default='pending')
    priority = SelectField('Priorité', choices=[
        ('low', 'Faible'), 
        ('medium', 'Moyenne'), 
        ('high', 'Élevée')
    ], default='medium')
    due_date = StringField('Date d\'échéance (AAAA-MM-JJ)')
    submit = SubmitField('Sauvegarder')

# =============== MODELS ===============

class Admin(UserMixin, db.Model):
    __tablename__ = 'admin'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la mise à jour de la dernière connexion admin: {e}")
    
    def is_admin(self):
        """Check if user is admin"""
        return True
    
    def get_id(self):
        """Get user ID for Flask-Login"""
        return str(self.id)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Relations
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la mise à jour de la dernière connexion utilisateur: {e}")
    
    def is_admin(self):
        """Check if user is admin"""
        return False
    
    def get_id(self):
        """Get user ID for Flask-Login"""
        return str(self.id)
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'status': self.status,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
        }

class Task(db.Model):
    __tablename__ = 'task'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    priority = db.Column(db.String(20), default='medium', nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        """Convert task object to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'priority': self.priority,
            'due_date': self.due_date.strftime('%Y-%m-%d') if self.due_date else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None,
            'user_id': self.user_id,
            'user_name': self.user.name if self.user else None
        }

# =============== UTILITIES ===============

def admin_required(f):
    """Decorator to restrict access to admin users only"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash("Accès refusé. Vous n'êtes pas administrateur.", 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    """Validate email address"""
    if not email or len(email) > 120:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if len(password) > 128:
        return False, "Le mot de passe ne peut pas dépasser 128 caractères"
    if not re.search(r'[A-Za-z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre"
    if not re.search(r'[0-9]', password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    return True, "Mot de passe valide"

def validate_phone(phone):
    """Validate phone number"""
    if not phone:
        return True  # Phone is optional
    
    # Clean the number (remove spaces, dashes, etc.)
    clean_phone = re.sub(r'[^\d+]', '', phone)
    
    # Check length (between 10 and 15 digits)
    if len(clean_phone) < 10 or len(clean_phone) > 15:
        return False
    
    return True

# =============== USER LOADER ===============

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    try:
        # Check if it's an admin first
        admin = db.session.get(Admin, int(user_id))
        if admin and admin.is_active:
            return admin
        
        # Otherwise check if it's a regular user
        user = db.session.get(User, int(user_id))
        if user and user.status == 'active':
            return user
    except (ValueError, TypeError):
        pass
    return None

# =============== CONTEXT PROCESSORS ===============

@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.now(timezone.utc)}

@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into templates"""
    return dict(csrf_token=generate_csrf)

# =============== ERROR HANDLERS ===============

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    try:
        return render_template('errors/404.html'), 404
    except:
        return "<h1>404 - Page Non Trouvée</h1><p>La page demandée n'existe pas.</p>", 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    app.logger.error(f'Erreur serveur: {error}')
    try:
        return render_template('errors/500.html'), 500
    except:
        return "<h1>500 - Erreur Serveur</h1><p>Une erreur interne s'est produite.</p>", 500

@app.errorhandler(413)
def too_large_error(error):
    """Handle file too large errors"""
    flash("Le fichier est trop volumineux (max 16MB)", 'danger')
    return redirect(request.url), 413

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    try:
        return render_template('errors/403.html'), 403
    except:
        return "<h1>403 - Accès Refusé</h1><p>Vous n'avez pas les permissions pour accéder à cette page.</p>", 403

# =============== SECURITY MIDDLEWARE ===============

@app.before_request
def security_headers():
    """Add security headers"""
    if request.endpoint == 'login' and request.method == 'POST':
        time.sleep(0.1)  # Prevent brute force attacks

@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if not app.debug and request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# =============== AUTHENTICATION ROUTES ===============

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('user_dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username_or_email = form.username.data.strip().lower()
        password = form.password.data
        remember_me = form.remember_me.data
        
        try:
            # Check admin
            admin = Admin.query.filter(
                db.or_(Admin.username == username_or_email, Admin.email == username_or_email)
            ).first()
            
            if admin and admin.is_active and bcrypt.check_password_hash(admin.password, password):
                login_user(admin, remember=remember_me)
                admin.update_last_login()
                flash(f"Bienvenue Admin {admin.username}!", 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
            
            # Check user
            user = User.query.filter_by(email=username_or_email).first()
            
            if user and bcrypt.check_password_hash(user.password, password):
                if user.status == 'pending':
                    flash("Votre compte est en attente d'approbation par l'administrateur.", 'warning')
                elif user.status == 'inactive':
                    flash("Votre compte est désactivé. Contactez l'administrateur.", 'danger')
                elif user.status == 'suspended':
                    flash("Votre compte est suspendu. Contactez l'administrateur.", 'danger')
                else:
                    login_user(user, remember=remember_me)
                    user.update_last_login()
                    flash(f"Bienvenue {user.name}!", 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('user_dashboard'))
            
            flash("Email/nom d'utilisateur ou mot de passe incorrect", 'danger')
            
        except Exception as e:
            app.logger.error(f"Erreur lors de la connexion: {e}")
            flash("Erreur lors de la connexion. Veuillez réessayer.", 'danger')
    
    return render_template('auth/login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User signup page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('user_dashboard'))
    
    form = SignupForm()
    
    if form.validate_on_submit():
        # Additional validations
        if User.query.filter_by(email=form.email.data.lower()).first() or Admin.query.filter_by(email=form.email.data.lower()).first():
            flash("Cet email est déjà utilisé", 'danger')
            return render_template('auth/signup.html', form=form)
        
        if form.phone.data and not validate_phone(form.phone.data):
            flash("Le numéro de téléphone n'est pas valide", 'danger')
            return render_template('auth/signup.html', form=form)
        
        is_valid_pwd, message = is_strong_password(form.password.data)
        if not is_valid_pwd:
            flash(message, 'danger')
            return render_template('auth/signup.html', form=form)
        
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                name=form.name.data.strip(),
                email=form.email.data.strip().lower(),
                password=hashed_password,
                phone=form.phone.data.strip() if form.phone.data else None,
                status='pending'
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash("Votre compte a été créé avec succès! Il sera activé après approbation par l'administrateur.", 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la création du compte: {e}")
            flash("Erreur lors de la création du compte. Veuillez réessayer.", 'danger')
    
    return render_template('auth/signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash("Vous avez été déconnecté", 'info')
    return redirect(url_for('login'))

# =============== DASHBOARDS ===============

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status = request.args.get('status', '', type=str)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    
    try:
        query = User.query
        
        if search:
            query = query.filter(
                db.or_(
                    User.name.contains(search),
                    User.email.contains(search)
                )
            )
        
        if status:
            query = query.filter_by(status=status)
        
        users = query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        stats = {
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(status='active').count(),
            'pending_users': User.query.filter_by(status='pending').count(),
            'inactive_users': User.query.filter_by(status='inactive').count(),
            'suspended_users': User.query.filter_by(status='suspended').count(),
            'recent_users': User.query.filter(
                User.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            ).count()
        }
        
        return render_template('admin/dashboard.html', users=users, stats=stats, search=search, status=status)
        
    except Exception as e:
        app.logger.error(f"Erreur dans le dashboard admin: {e}")
        flash("Erreur lors du chargement du dashboard", 'danger')
        return render_template('admin/dashboard.html', users=[], stats={}, search='', status='')

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    """User dashboard"""
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    
    try:
        tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.desc()).all()
        
        task_stats = {
            'total': len(tasks),
            'pending': len([t for t in tasks if t.status == 'pending']),
            'in_progress': len([t for t in tasks if t.status == 'in_progress']),
            'completed': len([t for t in tasks if t.status == 'completed'])
        }
        
        return render_template('user/dashboard.html', user=current_user, tasks=tasks, task_stats=task_stats)
        
    except Exception as e:
        app.logger.error(f"Erreur dans le dashboard utilisateur: {e}")
        flash("Erreur lors du chargement du dashboard", 'danger')
        return render_template('user/dashboard.html', user=current_user, tasks=[], task_stats={})

# =============== USER MANAGEMENT ===============

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def create():
    """Create new user"""
    form = CreateUserForm()
    
    if form.validate_on_submit():
        # Additional validations
        if User.query.filter_by(email=form.email.data.lower()).first() or Admin.query.filter_by(email=form.email.data.lower()).first():
            flash("Cet email est déjà utilisé", 'danger')
            return render_template('admin/create.html', form=form)
        
        if form.phone.data and not validate_phone(form.phone.data):
            flash("Le numéro de téléphone n'est pas valide", 'danger')
            return render_template('admin/create.html', form=form)
        
        is_valid_pwd, message = is_strong_password(form.password.data)
        if not is_valid_pwd:
            flash(message, 'danger')
            return render_template('admin/create.html', form=form)
        
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                name=form.name.data.strip(), 
                email=form.email.data.strip().lower(), 
                password=hashed_password,
                phone=form.phone.data.strip() if form.phone.data else None, 
                status=form.status.data,
                is_verified=True
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f"Utilisateur '{form.name.data}' ajouté avec succès!", 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la création de l'utilisateur: {e}")
            flash("Erreur lors de la création de l'utilisateur", 'danger')
    
    return render_template('admin/create.html', form=form)

@app.route('/admin/update/<int:id>', methods=['GET', 'POST'])
@admin_required
def update(id):
    """Update user"""
    user = db.session.get(User, id)
    if not user:
        flash("Utilisateur non trouvé", 'danger')
        return redirect(url_for('admin_dashboard'))
    
    form = UpdateUserForm(obj=user)
    
    if form.validate_on_submit():
        # Additional validations
        existing_user = User.query.filter(User.email == form.email.data.lower(), User.id != id).first()
        existing_admin = Admin.query.filter_by(email=form.email.data.lower()).first()
        if existing_user or existing_admin:
            flash("Cet email est déjà utilisé par un autre utilisateur", 'danger')
            return render_template('admin/update.html', form=form, user=user)
        
        if form.phone.data and not validate_phone(form.phone.data):
            flash("Le numéro de téléphone n'est pas valide", 'danger')
            return render_template('admin/update.html', form=form, user=user)
        
        if form.password.data:
            is_valid_pwd, message = is_strong_password(form.password.data)
            if not is_valid_pwd:
                flash(message, 'danger')
                return render_template('admin/update.html', form=form, user=user)
        
        try:
            user.name = form.name.data.strip()
            user.email = form.email.data.strip().lower()
            user.phone = form.phone.data.strip() if form.phone.data else None
            user.status = form.status.data
            
            if form.password.data:
                user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            db.session.commit()
            flash(f"Utilisateur '{user.name}' modifié avec succès!", 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la modification de l'utilisateur {id}: {e}")
            flash("Erreur lors de la modification de l'utilisateur", 'danger')
    
    return render_template('admin/update.html', form=form, user=user)

@app.route('/admin/approve_user/<int:id>')
@admin_required
def approve_user(id):
    """Approve user account"""
    try:
        user = db.session.get(User, id)
        if not user:
            flash("Utilisateur non trouvé", 'danger')
            return redirect(url_for('admin_dashboard'))
        
        user.status = 'active'
        user.is_verified = True
        db.session.commit()
        flash(f"Utilisateur '{user.name}' approuvé et activé!", 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de l'approbation de l'utilisateur {id}: {e}")
        flash("Erreur lors de l'approbation de l'utilisateur", 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_user/<int:id>')
@admin_required
def reject_user(id):
    """Reject user account"""
    try:
        user = db.session.get(User, id)
        if not user:
            flash("Utilisateur non trouvé", 'danger')
            return redirect(url_for('admin_dashboard'))
        
        user.status = 'inactive'
        db.session.commit()
        flash(f"Utilisateur '{user.name}' rejeté!", 'warning')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors du rejet de l'utilisateur {id}: {e}")
        flash("Erreur lors du rejet de l'utilisateur", 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/suspend_user/<int:id>')
@admin_required
def suspend_user(id):
    """Suspend user account"""
    try:
        user = db.session.get(User, id)
        if not user:
            flash("Utilisateur non trouvé", 'danger')
            return redirect(url_for('admin_dashboard'))
        
        user.status = 'suspended'
        db.session.commit()
        flash(f"Utilisateur '{user.name}' suspendu!", 'warning')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la suspension de l'utilisateur {id}: {e}")
        flash("Erreur lors de la suspension de l'utilisateur", 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:id>')
@admin_required
def delete(id):
    """Delete user and all related tasks"""
    try:
        user = db.session.get(User, id)
        if not user:
            flash("Utilisateur non trouvé", 'danger')
            return redirect(url_for('admin_dashboard'))
        
        user_name = user.name
        db.session.delete(user)
        db.session.commit()
        flash(f"Utilisateur '{user_name}' supprimé avec toutes ses tâches!", 'warning')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la suppression de l'utilisateur {id}: {e}")
        flash("Erreur lors de la suppression de l'utilisateur", 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/user/<int:id>')
@login_required
def view_user(id):
    """View user details"""
    user = db.session.get(User, id)
    if not user:
        flash("Utilisateur non trouvé", 'danger')
        return redirect(url_for('admin_dashboard' if current_user.is_admin() else 'user_dashboard'))
    
    if not current_user.is_admin() and current_user.id != id:
        flash("Accès refusé.", 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('users/view.html', user=user)

# =============== TASK MANAGEMENT ===============

@app.route('/tasks')
@login_required
def tasks():
    """List tasks with filtering and pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '', type=str)
        status_filter = request.args.get('status', '', type=str)
        priority_filter = request.args.get('priority', '', type=str)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        if current_user.is_admin():
            query = Task.query
        else:
            query = Task.query.filter_by(user_id=current_user.id)
        
        if search:
            query = query.filter(
                db.or_(
                    Task.title.contains(search),
                    Task.description.contains(search)
                )
            )
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        if priority_filter:
            query = query.filter_by(priority=priority_filter)
        
        tasks_paginated = query.order_by(Task.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        if current_user.is_admin():
            task_stats = {
                'total': Task.query.count(),
                'pending': Task.query.filter_by(status='pending').count(),
                'in_progress': Task.query.filter_by(status='in_progress').count(),
                'completed': Task.query.filter_by(status='completed').count()
            }
            return render_template('admin/tasks.html', 
                                 tasks=tasks_paginated, 
                                 stats=task_stats,
                                 search=search,
                                 status_filter=status_filter,
                                 priority_filter=priority_filter)
        else:
            return render_template('tasks/list.html', 
                                 tasks=tasks_paginated,
                                 search=search,
                                 status_filter=status_filter,
                                 priority_filter=priority_filter)
                                 
    except Exception as e:
        app.logger.error(f"Erreur lors du chargement des tâches: {e}")
        flash("Erreur lors du chargement des tâches", 'danger')
        return render_template('tasks/list.html', tasks=[])

@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    """Create new task"""
    form = TaskForm()
    
    if form.validate_on_submit():
        due_date = None
        if form.due_date.data:
            try:
                due_date = datetime.strptime(form.due_date.data, '%Y-%m-%d')
                if due_date.date() < datetime.now().date():
                    flash("La date d'échéance ne peut pas être dans le passé", 'danger')
                    return render_template('tasks/create.html', form=form)
            except ValueError:
                flash("Format de date invalide. Utilisez le format AAAA-MM-JJ", 'danger')
                return render_template('tasks/create.html', form=form)
        
        try:
            new_task = Task(
                title=form.title.data.strip(),
                description=form.description.data.strip() if form.description.data else None,
                status=form.status.data,
                priority=form.priority.data,
                due_date=due_date,
                user_id=current_user.id
            )
            
            db.session.add(new_task)
            db.session.commit()
            flash("Tâche créée avec succès!", 'success')
            return redirect(url_for('tasks'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la création de la tâche: {e}")
            flash("Erreur lors de la création de la tâche", 'danger')
    
    return render_template('tasks/create.html', form=form)

@app.route('/tasks/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update_task(id):
    """Update task"""
    task = db.session.get(Task, id)
    if not task:
        flash("Tâche non trouvée", 'danger')
        return redirect(url_for('tasks'))
    
    if not current_user.is_admin() and task.user_id != current_user.id:
        flash("Accès refusé.", 'danger')
        return redirect(url_for('tasks'))
    
    form = TaskForm(obj=task)
    if task.due_date:
        form.due_date.data = task.due_date.strftime('%Y-%m-%d')
    
    if form.validate_on_submit():
        due_date = None
        if form.due_date.data:
            try:
                due_date = datetime.strptime(form.due_date.data, '%Y-%m-%d')
            except ValueError:
                flash("Format de date invalide. Utilisez le format AAAA-MM-JJ", 'danger')
                return render_template('tasks/update.html', form=form, task=task)
        
        try:
            task.title = form.title.data.strip()
            task.description = form.description.data.strip() if form.description.data else None
            task.status = form.status.data
            task.priority = form.priority.data
            task.due_date = due_date
            
            db.session.commit()
            flash("Tâche modifiée avec succès!", 'success')
            return redirect(url_for('tasks'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la modification de la tâche {id}: {e}")
            flash("Erreur lors de la modification de la tâche", 'danger')
    
    return render_template('tasks/update.html', form=form, task=task)

@app.route('/tasks/<int:id>/delete')
@login_required
def delete_task(id):
    """Delete task"""
    try:
        task = db.session.get(Task, id)
        if not task:
            flash("Tâche non trouvée", 'danger')
            return redirect(url_for('tasks'))
        
        if not current_user.is_admin() and task.user_id != current_user.id:
            flash("Accès refusé.", 'danger')
            return redirect(url_for('tasks'))
        
        task_title = task.title
        db.session.delete(task)
        db.session.commit()
        flash(f"Tâche '{task_title}' supprimée avec succès!", 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la suppression de la tâche {id}: {e}")
        flash("Erreur lors de la suppression de la tâche", 'danger')
    
    return redirect(url_for('tasks'))

@app.route('/tasks/<int:id>')
@login_required
def view_task(id):
    """View task details"""
    task = db.session.get(Task, id)
    if not task:
        flash("Tâche non trouvée", 'danger')
        return redirect(url_for('tasks'))
    
    if not current_user.is_admin() and task.user_id != current_user.id:
        flash("Accès refusé.", 'danger')
        return redirect(url_for('tasks'))
    
    return render_template('tasks/view.html', task=task)

# =============== USER PROFILE ===============

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('users/profile.html', user=current_user)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    
    errors = []
    
    if not name:
        errors.append("Le nom est obligatoire")
    elif len(name) < 2 or len(name) > 100:
        errors.append("Le nom doit contenir entre 2 et 100 caractères")
    
    if phone and not validate_phone(phone):
        errors.append("Le numéro de téléphone n'est pas valide")
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('profile'))
    
    try:
        current_user.name = name
        current_user.phone = phone
        db.session.commit()
        flash("Profil mis à jour avec succès", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la mise à jour du profil: {e}")
        flash("Erreur lors de la mise à jour du profil", 'danger')
    
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    errors = []
    
    if not all([current_password, new_password, confirm_password]):
        errors.append("Tous les champs sont obligatoires")
    
    if not bcrypt.check_password_hash(current_user.password, current_password):
        errors.append("Mot de passe actuel incorrect")
    
    if new_password != confirm_password:
        errors.append("Les nouveaux mots de passe ne correspondent pas")
    
    is_valid_pwd, pwd_message = is_strong_password(new_password)
    if not is_valid_pwd:
        errors.append(pwd_message)
    
    if current_password == new_password:
        errors.append("Le nouveau mot de passe doit être différent de l'ancien")
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('profile'))
    
    try:
        hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_pw
        db.session.commit()
        flash("Mot de passe modifié avec succès", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors du changement de mot de passe: {e}")
        flash("Erreur lors du changement de mot de passe", 'danger')
    
    return redirect(url_for('profile'))

# =============== PUBLIC PAGES ===============

@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('user_dashboard'))
    return render_template('public/home.html')

@app.route('/home')
def home():
    """Redirect to index"""
    return redirect(url_for('index'))

@app.route('/about')
def about():
    """About page"""
    return render_template('public/about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page"""
    form = ContactForm()
    
    if form.validate_on_submit():
        try:
            # Process contact form
            name = form.name.data.strip()
            email = form.email.data.strip()
            subject = form.subject.data.strip()
            message = form.message.data.strip()
            
            # TODO: Implement message processing logic
            # (save to DB, send email, etc.)
            
            flash("Votre message a été envoyé avec succès! Nous vous répondrons dans les plus brefs délais.", 'success')
            return redirect(url_for('contact'))
            
        except Exception as e:
            app.logger.error(f"Erreur lors de l'envoi du message de contact: {e}")
            flash("Erreur lors de l'envoi du message. Veuillez réessayer.", 'danger')
    
    return render_template('public/contact.html', form=form)

@app.route('/pending')
def pending():
    """Pending approval page"""
    return render_template('auth/pending.html')

# =============== API ROUTES ===============

@app.route('/api/users')
@admin_required
def api_users():
    """API endpoint for users list"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        users_paginated = User.query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in users_paginated.items],
            'total': users_paginated.total,
            'pages': users_paginated.pages,
            'current_page': page,
            'per_page': per_page
        })
    except Exception as e:
        app.logger.error(f"Erreur API users: {e}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/users/<int:id>')
@login_required
def api_user(id):
    """API endpoint for single user"""
    if not current_user.is_admin() and current_user.id != id:
        return jsonify({'error': 'Accès refusé'}), 403
    
    try:
        user = db.session.get(User, id)
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        
        return jsonify(user.to_dict())
    except Exception as e:
        app.logger.error(f"Erreur API user {id}: {e}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/tasks')
@login_required
def api_tasks():
    """API endpoint for tasks list"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        if current_user.is_admin():
            query = Task.query
        else:
            query = Task.query.filter_by(user_id=current_user.id)
        
        tasks_paginated = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'tasks': [task.to_dict() for task in tasks_paginated.items],
            'total': tasks_paginated.total,
            'pages': tasks_paginated.pages,
            'current_page': page,
            'per_page': per_page
        })
    except Exception as e:
        app.logger.error(f"Erreur API tasks: {e}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/tasks/<int:id>')
@login_required
def api_task(id):
    """API endpoint for single task"""
    try:
        task = db.session.get(Task, id)
        if not task:
            return jsonify({'error': 'Tâche non trouvée'}), 404
        
        if not current_user.is_admin() and task.user_id != current_user.id:
            return jsonify({'error': 'Accès refusé'}), 403
        
        return jsonify(task.to_dict())
    except Exception as e:
        app.logger.error(f"Erreur API task {id}: {e}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/stats')
@admin_required
def api_stats():
    """API endpoint for admin statistics"""
    try:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        
        stats = {
            'users': {
                'total': User.query.count(),
                'active': User.query.filter_by(status='active').count(),
                'pending': User.query.filter_by(status='pending').count(),
                'inactive': User.query.filter_by(status='inactive').count(),
                'suspended': User.query.filter_by(status='suspended').count(),
                'recent': User.query.filter(User.created_at >= today).count()
            },
            'tasks': {
                'total': Task.query.count(),
                'pending': Task.query.filter_by(status='pending').count(),
                'in_progress': Task.query.filter_by(status='in_progress').count(),
                'completed': Task.query.filter_by(status='completed').count(),
                'overdue': Task.query.filter(
                    Task.due_date < datetime.now().date(),
                    Task.status != 'completed'
                ).count() if Task.query.first() else 0
            }
        }
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Erreur API stats: {e}")
        return jsonify({'error': 'Erreur serveur'}), 500

# =============== HEALTH CHECK ===============

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'disconnected',
            'error': str(e)
        }), 500

# =============== CLI COMMANDS ===============

@app.cli.command()
def init_db():
    """Initialize database"""
    db.create_all()
    print("Base de données initialisée!")

@app.cli.command()
def create_admin():
    """Create admin account"""
    username = input("Nom d'utilisateur admin: ")
    email = input("Email admin: ")
    password = input("Mot de passe admin: ")
    
    if Admin.query.filter_by(username=username).first():
        print("Ce nom d'utilisateur existe déjà!")
        return
    
    if not is_valid_email(email):
        print("Email invalide!")
        return
    
    is_valid_pwd, message = is_strong_password(password)
    if not is_valid_pwd:
        print(f"Mot de passe invalide: {message}")
        return
    
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = Admin(username=username, email=email, password=hashed_pw)
    db.session.add(admin)
    db.session.commit()
    print(f"Admin '{username}' créé avec succès!")

@app.cli.command()
def reset_db():
    """Reset database completely"""
    if input("Êtes-vous sûr de vouloir réinitialiser la base de données? (yes/no): ") == "yes":
        db.drop_all()
        db.create_all()
        
        hashed_pw = bcrypt.generate_password_hash("admin123").decode('utf-8')
        admin = Admin(username="admin", password=hashed_pw, email="admin@example.com")
        db.session.add(admin)
        db.session.commit()
        
        print("Base de données réinitialisée!")
        print("Admin par défaut créé: admin / admin123")

# =============== DATABASE INITIALIZATION ===============

with app.app_context():
    try:
        db.create_all()
        
        # Create default admin if it doesn't exist
        if not Admin.query.filter_by(username="admin").first():
            hashed_pw = bcrypt.generate_password_hash("admin123").decode('utf-8')
            admin = Admin(username="admin", password=hashed_pw, email="admin@example.com")
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Admin créé: admin / admin123")
    except Exception as e:
        app.logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")

# =============== APPLICATION LAUNCH ===============

if __name__ == "__main__":
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))