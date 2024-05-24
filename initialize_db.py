from app import db, User, app
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()

    # Optionally, create a test user if it doesn't already exist
    if not User.query.filter_by(email="test@example.com").first():
        hashed_password = bcrypt.generate_password_hash("password").decode('utf-8')
        test_user = User(email="test@example.com", password=hashed_password, email_confirmed=False)
        db.session.add(test_user)
        db.session.commit()

    # Print all users to check their email_confirmed status
    users = User.query.all()
    for user in users:
        print(f'User: {user.email}, Confirmed: {user.email_confirmed}')
