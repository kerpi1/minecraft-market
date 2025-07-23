from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import secrets
import string
import jwt

# Создание приложения Flask
app = Flask(__name__)
app.config.from_object('config.Config')

# Инициализация базы данных
db = SQLAlchemy(app)

# Инициализация системы логина
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Build(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    long_description = db.Column(db.Text)  # Для страницы сборки
    price = db.Column(db.Integer, nullable=False)  # Цена в рублях
    minecraft_version = db.Column(db.String(20))
    author = db.Column(db.String(100))  # Автор сборки
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)


class UserBuild(db.Model):
    """Эта таблица нужна для отслеживания покупок пользователей.
    Хотя мы используем LicenseKey, эта таблица может быть полезна
    для хранения дополнительной информации о покупке (дата покупки, сумма и т.д.)"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    build_id = db.Column(db.Integer, db.ForeignKey('build.id'))
    purchased_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)


class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    build_id = db.Column(db.Integer, db.ForeignKey('build.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Связи
    user = db.relationship('User', backref='licenses')
    build = db.relationship('Build', backref='licenses')


# Функция для генерации лицензионных ключей
def generate_license_key():
    """Генерирует уникальный лицензионный ключ"""
    characters = string.ascii_uppercase + string.digits
    key_parts = []
    for _ in range(4):
        part = ''.join(secrets.choice(characters) for _ in range(4))
        key_parts.append(part)
    return '-'.join(key_parts)


# Функции для работы с JWT
def generate_token(user_id):
    """Генерирует JWT токен для пользователя"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),  # Токен действует 24 часа
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')


def verify_token(token):
    """Проверяет JWT токен и возвращает user_id"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# Загрузчик пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Создание базы данных
with app.app_context():
    # Убедимся, что папка существует перед созданием таблиц
    database_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    database_dir = os.path.dirname(database_path)
    if not os.path.exists(database_dir):
        os.makedirs(database_dir)

    # Создаем все таблицы
    db.create_all()

    # Создание администратора по умолчанию
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@marketplace.local',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Администратор создан: логин 'admin', пароль 'admin123'")

    # Создание тестовых сборок если их нет
    try:
        if Build.query.count() == 0:
            test_builds = [
                Build(
                    name='SkyBlock Ultimate',
                    description='Современная сборка SkyBlock с уникальными механиками и балансом.',
                    long_description='Полное описание SkyBlock Ultimate. Эта сборка включает в себя множество уникальных механик, которые делают игру увлекательной и интересной. Здесь вы найдете сбалансированный геймплей с продуманными системами прогресса.',
                    price=999,
                    minecraft_version='1.19.2',
                    author='SkyTeam'
                ),
                Build(
                    name='TechCraft Pro',
                    description='Технологическая сборка с модами на автоматизацию и производство.',
                    long_description='Подробное описание TechCraft Pro. Сборка для тех, кто любит автоматизацию и технологии. Включает в себя лучшие технические моды, которые позволят вам создать настоящие заводы и автоматизированные системы.',
                    price=1499,
                    minecraft_version='1.18.2',
                    author='TechMasters'
                ),
                Build(
                    name='Magic World',
                    description='Магическая сборка с заклинаниями, магическими рудами и артефактами.',
                    long_description='Полное описание Magic World. Погрузитесь в мир магии и чародейства. Эта сборка предлагает уникальную магическую систему с заклинаниями, магическими рудами и мощными артефактами, которые помогут вам в ваших приключениях.',
                    price=1299,
                    minecraft_version='1.20.1',
                    author='MagicCrafters'
                )
            ]

            for build in test_builds:
                db.session.add(build)

            db.session.commit()
            print("Тестовые сборки созданы")
    except Exception as e:
        print(f"Ошибка при создании тестовых сборок: {e}")


# Маршруты
@app.route('/')
def index():
    # Получаем все активные сборки
    builds = Build.query.filter_by(is_active=True).all()

    # Если пользователь авторизован, получаем его лицензии
    user_licenses = []
    if current_user.is_authenticated:
        licenses = LicenseKey.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).all()
        user_licenses = [license.build_id for license in licenses]

    # Передаем datetime в контекст шаблона
    return render_template('index.html', builds=builds, user_licenses=user_licenses, datetime=datetime)


@app.route('/download')
def download_launcher():
    # Здесь будет логика скачивания лаунчера
    # Пока возвращаем заглушку
    flash('Лаунчер будет доступен для скачивания позже!', 'info')
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверное имя пользователя или пароль!', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует!', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Пользователь с такой почтой уже существует!', 'error')
            return render_template('register.html')

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/profile')
@login_required
def profile():
    # Передаем datetime в контекст шаблона
    return render_template('profile.html', datetime=datetime)


@app.route('/build/<int:build_id>')
def build_detail(build_id):
    build = Build.query.get_or_404(build_id)

    # Проверяем, куплена ли сборка текущим пользователем
    is_purchased = False
    if current_user.is_authenticated:
        license = LicenseKey.query.filter_by(
            user_id=current_user.id,
            build_id=build_id,
            is_active=True
        ).first()
        is_purchased = license is not None

    # Передаем datetime в контекст шаблона
    return render_template('build_detail.html', build=build, is_purchased=is_purchased, datetime=datetime)


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('index'))

    # Статистика
    total_users = User.query.count()
    total_builds = Build.query.count()
    total_sales = LicenseKey.query.count()

    # Все сборки
    builds = Build.query.all()

    # Все пользователи для выпадающего списка
    users = User.query.all()

    return render_template('admin.html',
                           total_users=total_users,
                           total_builds=total_builds,
                           total_sales=total_sales,
                           builds=builds,
                           users=users)


@app.route('/admin/create_build', methods=['POST'])
@login_required
def create_build():
    if not current_user.is_admin:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('index'))

    try:
        name = request.form.get('name')
        description = request.form.get('description')
        long_description = request.form.get('long_description')
        price = int(request.form.get('price'))
        minecraft_version = request.form.get('minecraft_version')
        author = request.form.get('author')

        # Создаем новую сборку
        new_build = Build(
            name=name,
            description=description[:200],  # Ограничиваем описание 200 символами
            long_description=long_description,
            price=price,
            minecraft_version=minecraft_version,
            author=author
        )

        db.session.add(new_build)
        db.session.commit()

        flash(f'Сборка "{name}" успешно создана!', 'success')
    except Exception as e:
        flash('Ошибка при создании сборки!', 'error')

    return redirect(url_for('admin'))


@app.route('/admin/edit_build/<int:build_id>', methods=['GET', 'POST'])
@login_required
def edit_build(build_id):
    if not current_user.is_admin:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('index'))

    build = Build.query.get_or_404(build_id)

    if request.method == 'POST':
        try:
            build.name = request.form.get('name')
            build.description = request.form.get('description')[:200]
            build.long_description = request.form.get('long_description')
            build.price = int(request.form.get('price'))
            build.minecraft_version = request.form.get('minecraft_version')
            build.author = request.form.get('author')
            build.is_active = 'is_active' in request.form

            db.session.commit()
            flash(f'Сборка "{build.name}" успешно обновлена!', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            flash('Ошибка при обновлении сборки!', 'error')

    return render_template('edit_build.html', build=build)


@app.route('/admin/grant_access', methods=['POST'])
@login_required
def grant_access():
    if not current_user.is_admin:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('index'))

    try:
        user_id = int(request.form.get('user_id'))
        build_id = int(request.form.get('build_id'))
        duration = request.form.get('duration')  # 5min, 30min, 1month

        # Определяем срок действия
        expires_at = None
        if duration == '5min':
            expires_at = datetime.utcnow() + timedelta(minutes=5)
        elif duration == '30min':
            expires_at = datetime.utcnow() + timedelta(minutes=30)
        elif duration == '1month':
            expires_at = datetime.utcnow() + timedelta(days=30)

        # Проверяем, существует ли уже лицензия для этого пользователя и сборки
        existing_license = LicenseKey.query.filter_by(
            user_id=user_id,
            build_id=build_id
        ).first()

        if existing_license:
            # Обновляем существующую лицензию
            existing_license.expires_at = expires_at
            existing_license.is_active = True
            # Генерируем новый ключ
            existing_license.key = generate_license_key()
            existing_license.created_at = datetime.utcnow()
            flash(f'Доступ к сборке успешно обновлен на {duration}!', 'success')
        else:
            # Создаем новую лицензию
            license_key = generate_license_key()
            new_license = LicenseKey(
                key=license_key,
                user_id=user_id,
                build_id=build_id,
                is_active=True,
                expires_at=expires_at
            )
            db.session.add(new_license)
            flash(f'Доступ к сборке успешно предоставлен на {duration}!', 'success')

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash('Ошибка при предоставлении доступа!', 'error')

    return redirect(url_for('admin'))


@app.route('/admin/revoke_access', methods=['POST'])
@login_required
def revoke_access():
    if not current_user.is_admin:
        flash('Доступ запрещен!', 'error')
        return redirect(url_for('index'))

    try:
        user_id = int(request.form.get('user_id'))
        build_id = int(request.form.get('build_id'))

        # Находим лицензию и деактивируем её
        license = LicenseKey.query.filter_by(
            user_id=user_id,
            build_id=build_id
        ).first()

        if license:
            license.is_active = False
            db.session.commit()
            flash('Доступ к сборке успешно отозван!', 'success')
        else:
            flash('Лицензия не найдена!', 'error')

    except Exception as e:
        db.session.rollback()
        flash('Ошибка при отзыве доступа!', 'error')

    return redirect(url_for('admin'))


@app.route('/purchase/<int:build_id>', methods=['POST'])
@login_required
def purchase_build(build_id):
    build = Build.query.get_or_404(build_id)

    # Проверяем, не куплена ли уже эта сборка (и не истекла ли)
    existing_license = LicenseKey.query.filter_by(
        user_id=current_user.id,
        build_id=build_id
    ).first()

    # Определяем срок действия (по умолчанию 1 месяц)
    expires_at = datetime.utcnow() + timedelta(days=30)

    if existing_license:
        # Если лицензия существует, обновляем её
        existing_license.expires_at = expires_at
        existing_license.is_active = True
        existing_license.key = generate_license_key()  # Генерируем новый ключ
        existing_license.created_at = datetime.utcnow()
        flash(f'Доступ к сборке "{build.name}" успешно продлен!', 'success')
    else:
        # Создаем новую лицензию
        license_key = generate_license_key()
        new_license = LicenseKey(
            key=license_key,
            user_id=current_user.id,
            build_id=build_id,
            is_active=True,
            expires_at=expires_at
        )

        db.session.add(new_license)
        flash(f'Поздравляем! Вы успешно приобрели сборку "{build.name}"!', 'success')

    db.session.commit()
    return redirect(url_for('profile'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы!', 'success')
    return redirect(url_for('index'))


# API эндпоинты для лаунчера
@app.route('/api/v1/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        # Проверяем учетные данные
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            # Генерируем токен
            token = generate_token(user.id)

            # Получаем список купленных сборок
            licenses = LicenseKey.query.filter_by(
                user_id=user.id,
                is_active=True
            ).all()

            builds = []
            for license in licenses:
                if license.build and (not license.expires_at or license.expires_at > datetime.utcnow()):
                    builds.append({
                        'id': license.build.id,
                        'name': license.build.name,
                        'version': license.build.minecraft_version
                    })

            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin
                },
                'builds': builds
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/builds', methods=['GET'])
def api_get_all_builds():
    try:
        # Получаем токен из заголовка
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header required'}), 401

        # Извлекаем токен
        token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else auth_header

        # Проверяем токен
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # Получаем пользователя
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Получаем все активные сборки
        builds = Build.query.filter_by(is_active=True).all()

        # Получаем лицензии пользователя
        user_licenses = LicenseKey.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        licensed_build_ids = [license.build_id for license in user_licenses
                              if not license.expires_at or license.expires_at > datetime.utcnow()]

        builds_data = []
        for build in builds:
            builds_data.append({
                'id': build.id,
                'name': build.name,
                'description': build.description,
                'version': build.minecraft_version,
                'price': build.price,
                'purchased': build.id in licensed_build_ids
            })

        return jsonify({
            'builds': builds_data
        }), 200

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/build/<int:build_id>')
def api_get_build(build_id):
    try:
        build = Build.query.get_or_404(build_id)
        return jsonify({
            'id': build.id,
            'name': build.name,
            'description': build.description,
            'long_description': build.long_description,
            'minecraft_version': build.minecraft_version,
            'price': build.price,
            'author': build.author
        }), 200
    except Exception as e:
        return jsonify({'error': 'Build not found'}), 404


# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)