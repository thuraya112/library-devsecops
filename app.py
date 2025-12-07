from sqlalchemy import text
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
import os

app = Flask(__name__)

# ===== إعدادات أساسية =====
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ===== موديل المستخدم =====
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # علاقة مع الكتب التي استعارها
    books = db.relationship('Book', backref='borrower', lazy=True)


# ===== موديل الكتاب =====
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year = db.Column(db.String(4), nullable=True)

    is_available = db.Column(db.Boolean, default=True)
    borrower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ===== إنشاء قاعدة البيانات + إضافة كتب تجريبية أول مرة =====
with app.app_context():
    if not os.path.exists('library.db'):
        db.create_all()

    # لو ما فيه كتب في الجدول نضيف شوية كتب
    if Book.query.first() is None:
        sample_books = [
            Book(title="Introduction to Cybersecurity", author="K. Smith", year="2021"),
            Book(title="Network Essentials", author="A. Johnson", year="2020"),
            Book(title="Python for Beginners", author="M. Lee", year="2019"),
            Book(title="Database Systems", author="J. Brown", year="2018"),
            Book(title="AI Basics", author="N. Davis", year="2022"),
        ]
        db.session.add_all(sample_books)
        db.session.commit()


# ===== الصفحة الرئيسية =====
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('books'))
    return redirect(url_for('login'))


# ===== Register =====
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('books'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # ✅ Server-side validation (Security)
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'warning')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'warning')
            return redirect(url_for('register'))

        # التأكد أن اليوزر أو الإيميل غير مكرر
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully. You can login now.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ===== Login =====
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('books'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # ✅ Basic validation
        if not username or not password:
            flash('Username and password are required.', 'warning')
            return redirect(url_for('login'))

        # مثال بسيط لمنع مدخلات غريبة جدًا (مو حماية كاملة لكن يبين اهتمامك)
        if len(username) < 3:
            flash('Invalid username.', 'warning')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('books'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


# ===== Logout =====
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ===== عرض كل الكتب =====
@app.route('/books')
@login_required
def books():
    all_books = Book.query.all()
    return render_template('books.html', books=all_books)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    query_str = ""

    if request.method == 'POST':
        query_str = request.form.get('q', '')
        results = Book.query.filter(Book.title.ilike(f"%{query_str}%")).all()
    return render_template('search.html', q=query_str, results=results)

@app.route('/echo', methods=['GET', 'POST'])
@login_required
def echo():
    message = ""
    if request.method == 'POST':
        message = request.form.get('message', '')
    return render_template('echo.html', message=message)

# ===== كتبي (الكتب المستعارة) =====
@app.route('/my-books')
@login_required
def my_books():
    my_books = Book.query.filter_by(borrower_id=current_user.id).all()
    return render_template('my_books.html', books=my_books)


# ===== استعارة كتاب =====
@app.route('/borrow/<int:book_id>')
@login_required
def borrow(book_id):
    book = Book.query.get_or_404(book_id)

    # لو الكتاب متوفر نقدر نستعيره
    if book.is_available:
        book.is_available = False
        book.borrower_id = current_user.id
        db.session.commit()
        flash(f'You borrowed "{book.title}".', 'success')
    else:
        flash('This book is not available.', 'warning')

    return redirect(url_for('books'))


# ===== إرجاع كتاب =====
@app.route('/return/<int:book_id>')
@login_required
def return_book(book_id):
    book = Book.query.get_or_404(book_id)

    # بس الشخص اللي مستعير الكتاب يقدر يرجعه
    if book.borrower_id != current_user.id:
        flash('You cannot return a book you did not borrow.', 'danger')
        return redirect(url_for('my_books'))

    book.is_available = True
    book.borrower_id = None
    db.session.commit()
    flash(f'You returned "{book.title}".', 'info')
    return redirect(url_for('my_books'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)