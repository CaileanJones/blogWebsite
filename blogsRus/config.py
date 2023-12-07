import os

#SQLAlchemy Config
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True

# Flask Forms Config
WTF_CSRF_ENABLED = True
SECRET_KEY = 'SRTE0)/*O~9X;J7ZCW^5%&=}#G8VS>_24AT@KN!?#{3F`$6]YU<'
