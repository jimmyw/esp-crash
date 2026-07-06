"""WSGI/CLI entrypoint. The app itself lives in app/ (app factory +
blueprints) - see app/__init__.py:create_app()."""
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run()
