from app import app, db
from sqlalchemy import text

def add_columns():
    with app.app_context():
        try:
            db.session.execute(text('ALTER TABLE files ADD COLUMN sandbox_trace_log TEXT;'))
        except Exception as e:
            print("sandbox_trace_log already exists or error:", e)
            
        try:
            db.session.execute(text('ALTER TABLE files ADD COLUMN sandbox_entropy FLOAT;'))
        except Exception as e:
            print("sandbox_entropy already exists or error:", e)
            
        try:
            db.session.execute(text('ALTER TABLE files ADD COLUMN sandbox_flags TEXT;'))
        except Exception as e:
            print("sandbox_flags already exists or error:", e)
            
        try:
            db.session.execute(text('ALTER TABLE files ADD COLUMN sandbox_risk_score INTEGER;'))
        except Exception as e:
            print("sandbox_risk_score already exists or error:", e)
            
        try:
            db.session.execute(text('ALTER TABLE files ADD COLUMN sandbox_status_detail VARCHAR(50);'))
        except Exception as e:
            print("sandbox_status_detail already exists or error:", e)
            
        db.session.commit()
        print("Migration finished!")

if __name__ == '__main__':
    add_columns()
