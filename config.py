from flask import Flask

import os


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "shoes_shop.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "\x03\x1f|\x1b\x95\x1b\xc2[\xec\x1a"
    JWT_TOKEN_LOCATION = "headers"
    JWT_HEADER_NAME = "X-API-KEY"
    JWT_HEADER_TYPE = "Bearer"
