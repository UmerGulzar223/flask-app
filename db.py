from app import db  # Adjust the import according to your project structure 

def clear_database():
    with app.app_context():  # Make sure to create the app context
        db.drop_all()  # This will drop all tables
        db.create_all()  # Optionally recreate the tables if needed

if __name__ == '__main__':
    clear_database()
