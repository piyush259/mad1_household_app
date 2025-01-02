

from flask import Flask
from models import db, Users
from routes import main
from flask_login import LoginManager





app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///household.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'SECRET_KEY'





login_manager = LoginManager(app)
login_manager.login_view = '/signin'
login_manager.init_app(app)
db.init_app(app)


app.register_blueprint(main)


# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Create tables and add default admin user if not exists
with app.app_context():
    db.create_all()
    admin = Users.query.filter_by(username='admin').first()
    if not admin:
        admin = Users(username='admin', password='admin', email='admin@admin.com',
                      phone_number='1234567890', role='admin', is_admin=True, name='admin')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
