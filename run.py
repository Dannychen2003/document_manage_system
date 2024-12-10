from app import create_app,db
from flask import Flask
from flask_migrate import Migrate

app = create_app()
migrate = Migrate(app, db)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=7777,debug=True)
