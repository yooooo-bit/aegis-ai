from flask import Flask

import config
from app import db
from app.routes import bp


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["TEMPLATES_AUTO_RELOAD"] = True  # edit a template, refresh the browser
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # evidence-bundle uploads are small
    db.init_db()
    app.register_blueprint(bp)
    return app
