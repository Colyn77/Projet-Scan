# app/models/schemas.py

from app.core.config import db
from datetime import datetime

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)


