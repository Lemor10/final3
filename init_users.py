from app import app, db, User
from datetime import datetime

with app.app_context():
    User.query.filter(User.created_at == None).update({User.created_at: datetime.utcnow()})
    db.session.commit()
    print("✅ User created_at updated")