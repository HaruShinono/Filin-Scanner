from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from concurrent.futures import ThreadPoolExecutor

db = SQLAlchemy()
executor = ThreadPoolExecutor(max_workers=2)

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'your-very-secret-key-change-this'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        from routes import main_routes 
        app.register_blueprint(main_routes)
        db.create_all()

    return app