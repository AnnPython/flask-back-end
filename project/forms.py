from werkzeug.security import check_password_hash
from flask_restplus import fields

from datetime import datetime

from project import db, ma, api


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name_user = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_user = db.Column(db.Boolean, nullable=False, default=False)
    not_active = db.Column(db.Boolean, nullable=False, default=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return "<name_user %s>" % self.name_user


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "name_user", "email",  "is_admin", "is_user", "not_active")


class Purchases(db.Model):
    id_purchase = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, index=True, default=datetime.utcnow)
    name = db.Column(db.String(120))
    brand = db.Column(db.String(120))
    season = db.Column(db.String(120))
    price = db.Column(db.Float)
    amount_purchase = db.Column(db.Integer)

    def __repr__(self):
        return "<id %s>" % self.id


class PurchasesSchema(ma.Schema):
    class Meta:
        fields = ("id_purchase", "date", "name", "season", "brand", "price", "amount_purchase")


class Sales(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, index=True, default=datetime.utcnow)
    purchase_id = db.Column(db.Integer, db.ForeignKey("purchases.id_purchase"))
    purchases = db.relationship("Purchases", backref="purchases")
    amount_sale = db.Column(db.Integer)
    total = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", backref="users")

    def __repr__(self):
        return "<id %s>" % self.id


class SalesSchema(ma.Schema):
    class Meta:
        fields = ("id", "date", "purchase_id", "purchases", "amount_sale", "total", "user_id", "user")


class ShowSchema(ma.Schema):
    class Meta:
        fields = ("id", "date", "purchase_id", "purchases", "amount_sale", "total", "user_id", "name_user", "not_active",
                  "user", "id_purchase",
                  "date", "name", "season", "brand", "price", "amount_purchase")


User_schema = UserSchema()
Users_schema = UserSchema(many=True)

Purchase_schema = PurchasesSchema()
Purchases_schema = PurchasesSchema(many=True)

Sale_schema = SalesSchema()
Sales_schema = SalesSchema(many=True)

Show_schema = ShowSchema()
Shows_schema = ShowSchema(many=True)

model_user = api.model("user", {
    "name_user": fields.String("Enter Name"),
    "email": fields.String("Enter Email"),
    "password": fields.String("Enter Password"),
    "is_admin": fields.Boolean(False),
    "is_user": fields.Boolean(False),
    "not_active": fields.Boolean(False)
})

model_user_login = api.model("user_user", {
    "name_user": fields.String("Enter Name"),
    "email": fields.String("Enter Email"),
    "password": fields.String("Enter Password"),
})

model_product = api.model("list", {
    "brand": fields.String("Enter brand"),
    "name": fields.String("Enter name"),
    "season": fields.String("Enter season"),
    "price": fields.Float("Enter price"),
    "amount_purchase": fields.Integer("Enter amount")
})

model_purchase = api.model("list_query", {
    "id_query": fields.String("Enter id_query"),
    "amount_purchase": fields.String("amount"),
    "total": fields.String("Enter total"),
    "date": fields.Float("Enter date"),
    "item_id": fields.Integer("Enter item_id"),
    "user_id": fields.Float("Enter user_id")
})

model_user_archive = api.model("archive", {
    "not_active": fields.Boolean(True)
})
