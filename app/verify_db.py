from sqlalchemy import create_engine
from app.models.base import Base
import sys

def verify_models():
    # Create synchronous engine for compilation checks
    engine = create_engine("sqlite:///:memory:", echo=True)
    try:
        Base.metadata.create_all(engine)
        print("SQLAlchemy models compiled and tables created successfully in SQLite memory!")
        sys.exit(0)
    except Exception as e:
        print(f"Error compiling SQLAlchemy models: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    verify_models()
