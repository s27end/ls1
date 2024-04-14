from flask import Flask, render_template, request, session, make_response, flash, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import redirect, url_for
from flask_babel import Babel
import uuid

app = Flask(__name__)
app.secret_key = 'dxT0"WojvG\Yf:!q5&A#ovn6#AJrs'
app.config['BABEL_DEFAULT_LOCALE'] = 'ru'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
babel = Babel()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(100))
    native_language = db.Column(db.String(50), nullable=False)
    target_language = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    sent_requests = db.relationship('LanguageExchangeRequest', foreign_keys='LanguageExchangeRequest.sender_id',
                                    backref='sender_user')
    received_requests = db.relationship('LanguageExchangeRequest', foreign_keys='LanguageExchangeRequest.receiver_id',
                                        backref='receiver_user')
    last_username_change = db.Column(db.DateTime)

    def get_full_name(self):
        return self.name if self.name else self.username

    @staticmethod
    def find_matching_users(current_user, search_query=None): # dwadwwdwd
        query = User.query.filter((User.target_language == current_user.native_language) &
                                  (User.native_language == current_user.target_language))
        if search_query:
            query = query.filter((User.username.ilike(f'%{search_query}%')) |
                                 (User.name.ilike(f'%{search_query}%')) |
                                 (User.native_language.ilike(f'%{search_query}%')) |
                                 (User.target_language.ilike(f'%{search_query}%')))
        return query.all()


class LanguageExchangeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_language = db.Column(db.String(50), nullable=False)
    receiver_language = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    language = db.Column(db.String(50), nullable=False)
    posts = db.relationship('Post', backref='thread', lazy='dynamic')


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    content = db.Column(db.Text, nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='post')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(500))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = db.relationship('User', backref='sent_messages')
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.body}>'


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='conversation', lazy='dynamic')
    participants = db.relationship('User', secondary='conversation_user_link')

    def __repr__(self):
        return f'<Conversation {self.id}>'


conversation_user_link = db.Table('conversation_user_link',
                                  db.Column('conversation_id', db.Integer, db.ForeignKey('conversation.id'),
                                            primary_key=True),
                                  db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True))


@app.route('/set_language/<language>')
def set_language(language):
    session['language'] = language
    return redirect(url_for('index'))


def get_locale():
    if 'language' in session:
        return session['language']
    return request.accept_languages.best_match(['en', 'es', 'de'])


babel.init_app(app, locale_selector=get_locale)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        native_language = request.form['native_language']
        target_language = request.form['target_language']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            username_exists = True
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username,
                            password=hashed_password,
                            name=name,
                            native_language=native_language,
                            target_language=target_language)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return redirect(url_for('news_list'))
    return render_template('register.html', username_exists=username_exists)


@app.route('/get_user_language')
def get_user_language():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'native_language': user.native_language,
                'target_language': user.target_language
            })
    return jsonify({'error': 'User not logged in or not found'}), 404


@app.route('/main_content', methods=['GET', 'POST'])
def main_content():
    return render_template('news_list.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin == 1
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
            else:
                session.permanent = False
            return redirect(url_for('news_list'))
        else:
            return render_template('login.html', invalid_login=True)
    else:
        if 'user_id' in session:
            return redirect(url_for('news_list'))
        return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/study_materials')
def study_materials():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        return render_template('materials.html', target_language=user.target_language)
    else:
        flash("Вам необходимо войти в систему, чтобы получить доступ к учебным материалам", "error")
        return redirect(url_for('login'))


@app.route('/news', methods=['GET', 'POST'])
def news_list():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
    else:
        flash("Вам необходимо войти в систему, чтобы создать тему", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        language = request.form['language']
        new_thread = Thread(title=title, language=language)
        db.session.add(new_thread)
        db.session.commit()
        return redirect(url_for('news_list'))
    threads = Thread.query.order_by(Thread.timestamp.desc()).all()
    return render_template('news_list.html', threads=threads, user=user)


@app.route('/news/<int:thread_id>', methods=['GET', 'POST'])
def news_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if request.method == 'POST':
        content = request.form['content']
        title = "No Title"
        new_post = Post(title=title, content=content, thread=thread)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('news_thread', thread_id=thread_id))

    posts = Post.query.filter_by(thread_id=thread.id).order_by(Post.timestamp.asc()).all()
    return render_template('news_thread.html', thread=thread, posts=posts)


@app.route('/delete_thread', methods=['POST'])
def delete_thread():
    if not session.get('user_id'):
        return 'Unauthorized', 401
    if not session.get('is_admin', False):
        return 'Forbidden', 403
    data = request.get_json()
    thread_id = data.get('thread_id')
    thread = Thread.query.get_or_404(thread_id)
    db.session.delete(thread)
    db.session.commit()
    return 'OK', 200


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user.id == comment.user_id or current_user.is_admin:
        db.session.delete(comment)
        db.session.commit()
        flash('Комментарий удален', 'success')
        return redirect(url_for('news_thread', thread_id=comment.post.thread_id))
    else:
        flash('У вас нет прав для удаления этого комментария', 'danger')
        return redirect(url_for('news_thread', thread_id=comment.post.thread_id))


@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    conversations = Conversation.query.filter().all()
    return render_template('messages.html', conversations=conversations, user=current_user, Message=Message)


@app.route('/conversations/<int:conversation_id>')
def conversation(conversation_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user_id = session['user_id']
    current_user = User.query.get(current_user_id)
    convo = Conversation.query.get_or_404(conversation_id)
    if current_user_id not in [participant.id for participant in convo.participants]:
        return make_response('Forbidden', 403)
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp.asc()).all()
    partner = next((user for user in convo.participants if user.id != current_user_id), None)
    return render_template('conversation.html', messages=messages, partner=partner,
                           user=current_user)


@app.route('/send_message/<int:receiver_id>', methods=['GET', 'POST'])
def send_message(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user_id = session['user_id']
    existing_conversation = Conversation.query.join(conversation_user_link).filter(
        conversation_user_link.c.user_id.in_([current_user_id, receiver_id])
    ).first()
    if existing_conversation:
        conversation_id = existing_conversation.id
    else:
        new_conversation = Conversation(participants=[User.query.get(current_user_id), User.query.get(receiver_id)])
        db.session.add(new_conversation)
        db.session.commit()
        conversation_id = new_conversation.id
    if request.method == 'POST':
        body = request.form['message']
        new_message = Message(body=body, sender_id=current_user_id, conversation_id=conversation_id)
        db.session.add(new_message)
        db.session.commit()
    return redirect(url_for('conversation', conversation_id=conversation_id))


@app.route('/requests', methods=['GET', 'POST'])
def requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    show_request_error = False
    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        receiver = User.query.filter_by(username=receiver_username).first()
        if receiver:
            if receiver == current_user or receiver.is_admin:
                flash("Вы не можете отправить заявку этому пользователю", "error")
            else:
                existing_request = LanguageExchangeRequest.query.filter_by(sender_id=current_user.id,
                                                                           receiver_id=receiver.id).first()
                if not existing_request:
                    new_request = LanguageExchangeRequest(sender_id=current_user.id,
                                                          receiver_id=receiver.id,
                                                          sender_language=current_user.native_language,
                                                          receiver_language=receiver.target_language,
                                                          status='pending')
                    db.session.add(new_request)
                    db.session.commit()
                else:
                    show_request_error = True
        else:
            flash("Пользователь с таким именем не найден", "error")

    potential_partners = User.query.filter(User.id != current_user.id, User.is_admin == False).all()
    sent_requests = LanguageExchangeRequest.query.filter_by(sender_id=current_user.id).all()
    sent_to_users = [request.receiver_id for request in sent_requests]
    received_requests = LanguageExchangeRequest.query.filter_by(receiver_id=current_user.id).all()
    existing_partners = [request.sender_id for request in received_requests]
    potential_partners = [user for user in potential_partners if user.id not in sent_to_users and
                          user.id not in existing_partners]
    return render_template('requests.html',
                           potential_partners=potential_partners,
                           language_requests_sent=sent_requests,
                           language_requests_received=received_requests,
                           show_request_error=show_request_error)


@app.route('/update_request_status/<int:request_id>', methods=['POST'])
def update_request_status(request_id):
    status = request.form.get('status')
    request_obj = LanguageExchangeRequest.query.get(request_id)
    if request_obj:
        request_obj.status = status
        db.session.commit()
    return redirect(url_for('requests'))


@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    request = LanguageExchangeRequest.query.get(request_id)
    if request and request.receiver_id == session['user_id']:
        request.status = 'accepted'
        db.session.commit()
        existing_conversation = Conversation.query.join(conversation_user_link).filter(
            conversation_user_link.c.user_id.in_([request.sender_id, request.receiver_id])
        ).first()
        if not existing_conversation:
            new_conversation = Conversation(participants=[
                User.query.get(request.sender_id),
                User.query.get(request.receiver_id)
            ])
            db.session.add(new_conversation)
            db.session.commit()

        flash("Заявка принята", "success")
    else:
        flash("Ошибка при принятии заявки", "error")
    return redirect(url_for('requests'))


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    request = LanguageExchangeRequest.query.get(request_id)
    if request and request.receiver_id == session['user_id']:
        request.status = 'rejected'
        db.session.commit()
        flash("Заявка отклонена", "success")
    else:
        flash("Ошибка при отклонении заявки", "error")
    return redirect(url_for('requests'))


@app.route('/calls')
def calls():
    return render_template('calls.html')


@app.route('/start_call')
def start_call():
    room_name = str(uuid.uuid4())
    return redirect(f"https://meet.jit.si/{room_name}", code=302)


@app.route('/settings')
def settings():
    return render_template('settings.html')


@app.route('/change_username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    if current_user.last_username_change:
        time_since_last_change = datetime.utcnow() - current_user.last_username_change
        if time_since_last_change.days < 30:
            flash("Вы можете менять ник только раз в месяц", "error")
            return redirect(url_for('settings'))
    new_username = request.form.get('new_username')
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user:
        flash("Пользователь с таким ником уже существует", "error")
        return redirect(url_for('settings'))
    current_user.username = new_username
    current_user.last_username_change = datetime.utcnow()
    db.session.commit()
    flash("Ник успешно изменен", "success")
    return redirect(url_for('settings'))


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if not check_password_hash(current_user.password, current_password):
        flash("Текущий пароль неверен", "error")
        return redirect(url_for('settings'))
    if new_password != confirm_password:
        flash("Новый пароль и подтверждение не совпадают", "error")
        return redirect(url_for('settings'))
    hashed_password = generate_password_hash(new_password)
    current_user.password = hashed_password
    db.session.commit()
    flash("Пароль успешно изменен", "success")
    return redirect(url_for('settings'))


@app.route('/change_target_language', methods=['POST'])
def change_target_language():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = db.session.get(User, session['user_id'])
    new_target_language = request.form.get('new_target_language')
    if new_target_language == current_user.native_language:
        flash("Вы не можете выбирать свой родной язык", "error")
        return redirect(url_for('settings'))
    if new_target_language == current_user.target_language:
        flash("Вы уже изучаете этот язык", "error")
        return redirect(url_for('settings'))
    current_user.target_language = new_target_language
    db.session.commit()
    flash("Изучаемый язык успешно изменен", "success")
    return redirect(url_for('settings'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            hashed_password = generate_password_hash('admin_password')
            admin = User(
                username='admin',
                password=hashed_password,
                name='Admin',
                native_language='en',
                target_language='en',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)