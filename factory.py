# factory.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from concurrent.futures import ProcessPoolExecutor

# 1. Khởi tạo các đối tượng mở rộng mà không liên kết với app nào cả
db = SQLAlchemy()
executor = ProcessPoolExecutor(max_workers=2)

# 2. Tạo một hàm "Application Factory"
def create_app():
    """
    Hàm này chịu trách nhiệm tạo và cấu hình đối tượng ứng dụng Flask.
    """
    app = Flask(__name__)

    # Cấu hình cho ứng dụng
    app.config['SECRET_KEY'] = 'shinono-45ussr-135rss-991srs'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # 3. Liên kết các đối tượng mở rộng với app
    db.init_app(app)

    # 4. Import và đăng ký các route (Blueprint là cách tốt hơn, nhưng import trực tiếp vẫn được)
    with app.app_context():
        # Import các route ở đây để tránh circular import
        from routes import main_routes # Chúng ta sẽ tạo file routes.py ở bước sau
        app.register_blueprint(main_routes)

        # Tạo database nếu chưa có
        db.create_all()

    return app