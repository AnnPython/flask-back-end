from flask import request, jsonify
from marshmallow import fields, validate, ValidationError
from project.forms import User, Purchases, Sales, Purchases_schema, Users_schema, Sales_schema, Shows_schema
from werkzeug.security import generate_password_hash
from flask_restplus import Resource
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    JWTManager, current_user, jwt_required
)


from sqlalchemy.sql import func

from project import app

import re
import jwt

from project.forms import api, db, model_user, model_user_login, model_product, model_user_archive


jwt = JWTManager(app)


PASSWORD_VALIDATION = validate.Regexp(
    "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-zA-Z]){7,16}",
    error="Password must contain at least one letter, at"
    " least one number, be longer than six characters."
    "and shorter than 16.",
)

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@api.route("/registration")
class RegistrationUser(Resource):
    @api.expect(model_user)
    def post(self):
        """registration for new users"""
        email_data = request.get_json(["email"])
        check_email = User.query.filter_by(email=email_data["email"]).first()
        if check_email:
            return {'message': "User with current email exist"}
        if not EMAIL_REGEX.match(email_data["email"]):
            return {'message': "bad email, try again"}
        data = request.get_json(["password"])
        try:
            PASSWORD_VALIDATION(data["password"])
        except ValidationError as err:
            return {"message": err.messages}
        hashed_password = generate_password_hash(data["password"])
        new_user = User(
            name_user=request.json["name_user"], email=request.json["email"],
            password=hashed_password, is_admin=request.json["is_admin"],
            is_user=request.json["is_user"]
        )
        db.session.add(new_user)
        db.session.commit()
        return{'message': "user has been registered"}


@api.route("/login")
class LoginUsers(Resource):
    @api.expect(model_user_login)
    def post(self):
        """login for users"""
        user_email = request.get_json(["email"])
        user = User.query.filter_by(email=user_email["email"]).first()
        check_pass = request.get_json(["password"])
        if not user or not user.check_password(check_pass["password"]):
            return {"message": "user email or password is incorrect"}, 401
        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)
        return jsonify(access_token=access_token, refresh_token=refresh_token)


@api.route("/delete-user/<int:user_id>")
class DeleteUser(Resource):
    @jwt_required()
    def delete(self, user_id):
        """
        if customer has purchases it can`t be deleted
        """
        if not current_user.is_admin:
            return {"message": "Access denied"}
        if not Sales.query.filter_by(user_id=user_id).first():
            user = User.query.get_or_404(user_id)
            db.session.delete(user)
            db.session.commit()
            return{"message": "The user has been deleted"}
        else:
            return {"message": "Can`t delete, archive it instead"}


@api.route("/archive-user/<int:user_id>")
class DeleteUser(Resource):
    @jwt_required()
    @api.expect(model_user_archive)
    def patch(self, user_id):
        """
        For admin to archive user
        if customer has purchases it can not be deleted
        """
        if not current_user.is_admin:
            return {"message": "Access denied"}
        if Sales.query.filter_by(user_id=user_id).first():
            user_data = User.query.get_or_404(user_id)
            update_data = request.get_json()
            if user_data:
                user_data.not_active = update_data['not_active']
                db.session.add(user_data)
                db.session.commit()
                return{"message": "The user has been archived"}
        else:
            return {"message": "There is no such user. Try again"}


@api.route("/update-user/<int:user_id>")
class UpdateUser(Resource):
    @jwt_required()
    @api.expect(model_user_login)
    def put(self, user_id):
        """ Update user info"""
        if not current_user.is_admin:
            return {"message": "Access denied"}
        item_data = User.query.get_or_404(user_id)
        update_data = request.get_json()
        # if not item_data:
        #     return {"message": "There is no such user. Try again"}
        item_data.name_user = update_data['name_user']
        item_data.email = update_data['email']
        item_data = Users_schema.load(update_data)
        db.session.add(item_data)
        db.session.commit()
        return {"message": "Updated"}


@api.route("/show-users")
class ShowAllUsers(Resource):
    @jwt_required()
    def get(self):
        """Show all users only for admin"""
        if not current_user.is_admin:
            return {"message": "Access denied"}
        else:
            return jsonify(Users_schema.dump(User.query.all()))


@api.route("/user_identity")
class CurrentUser(Resource):
    @jwt_required()
    def get(self):
        """show info about current user"""
        if current_user.not_active:
            return {"message": "Access denied"}
        return jsonify(id=current_user.id, name_user=current_user.name_user, email=current_user.email)


@api.route("/add-catalog")
class AddProduct(Resource):
    @jwt_required()
    @api.expect(model_product)
    def post(self):
        """only admin can add product to the catalog"""
        if not current_user.is_admin:
            return{"message": "Access denied"}
        new_item = Purchases(name=request.json["name"], brand=request.json["brand"],
                             season=request.json["season"], price=request.json["price"],
                             amount_purchase=request.json["amount_purchase"])
        db.session.add(new_item)
        db.session.commit()
        return{"message": "Product added to catalog"}


@api.route("/update-product/<int:id_purchase>")
class UpdateProduct(Resource):
    @jwt_required()
    @api.expect(model_product)
    def put(self, id_purchase):
        """ admin can update catalog"""
        if not current_user.is_admin:
            return {"message": "Access denied"}
        else:
            product_data = Purchases.query.get_or_404(id_purchase)
            update_data = request.get_json()
            product_data.name = update_data['name']
            product_data.brand = update_data['brand']
            product_data.season = update_data['season']
            product_data.price = update_data['price']
            product_data.amount_purchase = update_data['amount_purchase']
            product_data = Purchases_schema.load(update_data)
            db.session.add(product_data)
            db.session.commit()
            return {"message": "Product has been updated"}


@api.route("/sale-from-catalog/<int:id_product>/<int:amount_select>")
class AddSales(Resource):
    @jwt_required()
    def post(self, id_product, amount_select):
        """
        customers can buy product from catalog,
        in case user had purchases above 5000 it can get discount 5%
        for the next one
        """
        if current_user.is_admin or current_user.not_active:
            return{"message": "Access denied"}
        select_product = Purchases.query.filter_by(id_purchase=id_product).first()
        if not select_product:
            return {"message": "There is no such product"}
        customer_quantity_sales = Sales.query.add_columns(Sales.amount_sale)\
            .with_entities(func.sum(Sales.amount_sale).label("sum_quantity"))\
            .filter(Sales.purchase_id == id_product)
        customer_sum_sales = Sales.query.add_columns(Sales.total)\
            .with_entities(func.sum(Sales.total).label("sum_sales"))\
            .filter(Sales.user_id == current_user.id)
        if customer_quantity_sales and customer_sum_sales:
            for items in customer_quantity_sales:
                if items.sum_quantity is None:
                    if amount_select > select_product.amount_purchase:
                        return {"message": f"Product: {select_product.name} left only {select_product.amount_purchase}"}
                else:
                    if amount_select > (select_product.amount_purchase - int(items.sum_quantity)):
                        return {"message": f"Product: {select_product.name} left only {(select_product.amount_purchase - int(items.sum_quantity))}"}
            for line in customer_sum_sales:
                if line.sum_sales is not None and int(line.sum_sales) >= 5000:
                    customer_purchase = int(amount_select) * (select_product.price - (select_product.price * 0.05))
                else:
                    customer_purchase = int(amount_select) * select_product.price
                select_item = Sales(amount_sale=amount_select, total=customer_purchase, user_id=current_user.id,
                                    purchase_id=select_product.id_purchase)
                db.session.add(select_item)
                db.session.commit()
                return {"message": "Product was selected"}


@api.route("/show-all-product")
class ShowAllProduct(Resource):
    @jwt_required()
    def get(self):
        """show catalog for all users"""
        if current_user.not_active:
            return {"message": "Access denied"}
        return jsonify(Purchases_schema.dump(Purchases.query.all()))


@api.route("/all-sold-product")
class QueryAdminList(Resource):
    @jwt_required()
    def get(self):
        """for admin to see all sold product list"""
        if not current_user.is_admin:
            return{"message": "Access denied"}
        query_data = Sales.query\
            .join(User, Purchases)\
            .add_columns(User.id, User.name_user,
                         Purchases.id_purchase, Purchases.price, Sales.amount_sale, Sales.total,
                         Sales.date, Sales.purchase_id)\
            .all()
        return jsonify(Sales_schema.dump(query_data))


@api.route("/query-admin-sold-item/<id_item>")
class QueryAdminItem(Resource):
    @jwt_required()
    def get(self, id_item):
        """query for admin to see how many items of current product were sold"""
        if not current_user.is_admin:
            return{"message": "Access denied"}
        query_item = Sales.query\
            .join(User, Purchases)\
            .add_columns(User.id, Purchases.name, Sales.amount_sale, Sales.total, Sales.date)\
            .filter(Purchases.id_purchase == id_item)\
            .all()
        return jsonify(Shows_schema.dump(query_item))


@api.route("/sum-customer-product/<id_customer>/<date_start>/<date_end>")
class SumCustomerPurchases(Resource):
    @jwt_required()
    def get(self, id_customer, date_start, date_end):
        """
        sum of purchases for current user you can set period
        date in format yyyy-mm-dd
        """
        if not current_user.is_admin:
            return{"message": "Access denied"}
        query_data = Sales.query.join(User, Purchases)\
            .add_columns(Sales.total).with_entities(func.sum(Sales.total).label("sum"))\
            .filter(User.id == id_customer, Sales.date.between(date_start, date_end))\
            .all()
        for item in query_data:
            if item.sum is not None:
                return {"message": f" Sum of all customer purchases {int(item.sum)} for user id {id_customer} "}
            else:
                return {"message": "User does not have purchase or try another user"}


@api.route("/discount-for-users")
class UserDiscount(Resource):
    @jwt_required()
    def get(self):
        """customers can check discount for purchases over sum>=5000"""
        if current_user.is_admin or current_user.not_active:
            return{"message": "Access denied"}
        query_sum = Sales.query.add_columns(Sales.total).with_entities(
            func.sum(Sales.total).label("sum"))\
            .filter(Sales.user_id == current_user.id)
        if query_sum:
            for item in query_sum:
                if item.sum is not None and int(item.sum) >= 5000:
                    return {"message": f" Sum of all your purchases {int(item.sum)} Your have discount 5% "}
                else:
                    return {"message": "Your don't have discount"}


@api.route("/list-purchases-for-users")
class CustomerListPurchases(Resource):
    @jwt_required()
    def get(self):
        """for customers to see their all purchase list"""
        if current_user.is_admin or current_user.not_active:
            return{"message": "Access denied"}
        query_data = Sales.query.join(User, Purchases)\
            .add_columns(User.name_user, Sales.purchase_id,
                         Sales.amount_sale, Sales.total,
                         Sales.date).filter(User.id == current_user.id)\
            .all()
        return jsonify(Sales_schema.dump(query_data))


@api.route("/query-admin-sales-by-date/<date_start>/<date_end>")
class QueryPeriod(Resource):
    @jwt_required()
    def get(self, date_start, date_end):
        """for admin to see list for current date"""
        if current_user.is_admin:
            query_data = Sales.query.join(Purchases, User)\
                .add_columns(Purchases.name, Sales.amount_sale, Sales.total, Sales.date, User.name_user)\
                .filter(Sales.date.between(date_start, date_end))\
                .all()
            return jsonify(Shows_schema.dump(query_data))
        else:
            return{"message": "Access denied"}
