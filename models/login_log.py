from datetime import datetime

from extensions import db


class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, default=0)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    status = db.Column(db.String(20))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
