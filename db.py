from flask import g
import mysql.connector

class DBConnector:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.app.teardown_appcontext(self.disconnect)

    def _get_config(self):
        return {
            'user': self.app.config["MYSQL_USER"],
            'password': self.app.config["MYSQL_PASSWORD"],
            'host': self.app.config["MYSQL_HOST"],
            'database': self.app.config["MYSQL_DATABASE"]
        }

    def connect(self):
        if 'db' not in g:
            g.db = mysql.connector.connect(use_pure = True, **self._get_config())
        return g.db
    
    def disconnect(self, exception=None):
        if 'db' in g:
            g.db.close()
        g.pop('db', None)