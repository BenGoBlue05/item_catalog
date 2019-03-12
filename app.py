#!/usr/bin/env python3

from flask import Flask, render_template, make_response, flash, request
from flask import redirect, url_for, jsonify
from flask import session as login_session
import random
import string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, User, GarageSale, Item
import json
from google.oauth2 import id_token
from google.auth.transport import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read()
)['web']['client_id']

DB_NAME = 'sqlite:///garagesale.db'
engine = create_engine(DB_NAME, connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# json response for all garage sales
@app.route('/garagesales/json/')
def garage_sales_json():
    sales = session.query(GarageSale).all()
    return jsonify([i.serialize for i in sales])


# home page
@app.route('/')
@app.route('/garagesales/')
def show_garage_sales():
    garage_sales = session.query(GarageSale).all()
    return render_template('garage_sales.html', garage_sales=garage_sales)


# add new garage sale
@app.route('/garagesales/new/', methods=['GET', 'POST'])
def add_garage_sale():
    # go to login screen if not logged in
    if 'username' not in login_session:
        return redirect(url_for('show_login'))
    if request.method == 'POST':
        sale = GarageSale(
            name=request.form['name'],
            address=request.form['address'],
            user_id=login_session['user_id']
        )
        session.add(sale)
        session.commit()
        flash("The Garage Sale has been successfully created!")
        return redirect(url_for('show_garage_sales'))
    else:
        return render_template('add_garage_sale.html')


# edit garage sale
@app.route('/garagesales/<garage_sale_id>/edit/', methods=['GET', 'POST'])
def edit_garage_sale(garage_sale_id):
    # go to login screen if not logged in
    if 'username' not in login_session:
        return redirect(url_for('show_login'))
    sale = session.query(GarageSale).filter_by(id=garage_sale_id).one()
    # prevent user from editing garage sale they did not create
    if login_session['user_id'] != sale.user_id:
        flash("You were not authorized to access that page.")
        return redirect(url_for('show_garage_sales'))
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        if name:
            sale.name = name
        if address:
            sale.address = address
        session.add(sale)
        session.commit()
        flash("Your changes have been saved!")
        return redirect(url_for('show_garage_sales'))
    else:
        return render_template('edit_garage_sale.html', garage_sale=sale)


# delete garage sale
@app.route(
    '/garagesales/<int:garage_sale_id>/delete/',
    methods=['GET', 'POST']
)
def delete_garage_sale(garage_sale_id):
    sale = session.query(GarageSale).filter_by(id=garage_sale_id).one()
    if 'username' not in login_session:
        return redirect(url_for('show_login'))
    if login_session['user_id'] != sale.user_id:
        flash("You were not authorized to access that page.")
        return redirect(url_for('show_garage_sales'))
    if request.method == 'POST':
        session.delete(sale)
        session.commit()
        flash("%s has been deleted" % sale.name)
        return redirect(url_for('show_garage_sales'))
    else:
        return render_template('delete_garage_sale.html', garage_sale=sale)


# json response for all items for a particular garage sale
@app.route('/garagesales/<int:garage_sale_id>/items')
def garage_sale_items_json(garage_sale_id):
    items = session.query(Item).filter_by(garage_sale_id=garage_sale_id).all()
    return jsonify([i.serialize for i in items])


# json response for item details
@app.route('/item/<int:item_id>')
def item_details_json(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item.serialize)


# show all items for sale for a particular garage sale
@app.route('/garagesales/<int:garage_sale_id>/', )
@app.route('/garagesales/<int:garage_sale_id>/items/')
def show_garage_sale_details(garage_sale_id):
    sale = session.query(GarageSale).filter_by(id=garage_sale_id).one()
    items = session.query(Item).filter_by(garage_sale_id=garage_sale_id).all()
    return render_template('garage_sale_details.html',
                           garage_sale=sale, products=items)


# add item
@app.route(
    '/garagesales/<int:garage_sale_id>/items/new',
    methods=['GET', 'POST']
)
def new_item(garage_sale_id):
    # go to login screen if not logged in
    if 'username' not in login_session:
        return redirect(url_for('show_login'))
    if request.method == 'POST':
        name = request.form['name']
        item = Item(
            name=name,
            description=request.form['description'],
            price=request.form['price'],
            garage_sale_id=garage_sale_id,
            user_id=login_session['user_id']
        )
        session.add(item)
        session.commit()
        flash("%s has beed added to your garage sale!" % name)
        return redirect(url_for('show_garage_sale_details',
                                garage_sale_id=garage_sale_id))
    else:
        return render_template('new_item.html', garage_sale_id=garage_sale_id)


# edit item
@app.route(
    '/garagesales/<int:garage_sale_id>/items/<int:item_id>/edit/',
    methods=['GET', 'POST']
)
def edit_item(garage_sale_id, item_id):
    # go to login screen if not logged in
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('show_login'))

    item = session.query(Item).filter_by(id=item_id).one()
    # prevent user from editing item that they did not create
    if login_session['user_id'] != item.user_id:
        flash("You are not authorized to access that page.")
        return redirect(url_for('show_garage_sale_details',
                                garage_sale_id=garage_sale_id))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        if name:
            item.name = name
        if description:
            item.description = description
        if price:
            item.price = price
        session.add(item)
        session.commit()
        flash("The changes have been saved!")
        return redirect(url_for('show_garage_sale_details',
                                garage_sale_id=garage_sale_id))
    else:
        return render_template('edit_item.html',
                               garage_sale_id=garage_sale_id, item=item)


# delete item
@app.route(
    '/garagesales/<int:garage_sale_id>/items/<int:item_id>/delete/',
    methods=['GET', 'POST']
)
def delete_item(garage_sale_id, item_id):
    # go to login screen if not logged in
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('show_login'))
    item = session.query(Item).filter_by(id=item_id).one()
    # prevent user from deleting item that they did not create
    if login_session['user_id'] != item.user_id:
        flash("You are not authorized to access that page.")
        return redirect(url_for('show_garage_sale_details',
                                garage_sale_id=garage_sale_id))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Successfully deleted")
        return redirect(url_for('show_garage_sale_details',
                                garage_sale_id=garage_sale_id))
    else:
        return render_template('delete_item.html',
                               garage_sale_id=garage_sale_id, item=item)


# show item details
@app.route('/garagesales/<garage_sale_id>/items/<item_id>')
@app.route('/garagesales/<garage_sale_id>/items/<item_id>')
def show_item_details(garage_sale_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    sale = session.query(GarageSale).filter_by(id=garage_sale_id).one()
    return render_template('item_details.html', item=item, garage_sale=sale)


# login
@app.route('/login/')
def show_login():
    print("login")
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    state = request.args.get('state')
    if state != login_session['state']:
        print("STATE = %s" % state)
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # get auth code
    token = request.data
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        id_info = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            message = "Wrong issuer."
            response = make_response(json.dumps(message), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        google_id = id_info['sub']

        stored_access_token = login_session.get('access_token')

        if stored_access_token is not None and stored_access_token == google_id:
            x = 'Current user is already connected.'
            response = make_response(json.dumps(x), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store token in the session
        login_session['access_token'] = google_id

        login_session['username'] = id_info['name']
        login_session['picture'] = id_info['picture']
        login_session['email'] = id_info['email']

        user_id = get_user_id(login_session['email'])
        if not user_id:
            user_id = create_user()
        login_session['user_id'] = user_id

        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        flash("you are now logged in as %s" % login_session['username'])
        print("done!")
        return output

    except ValueError:
        message = "Invalid token"
        response = make_response(json.dumps(message), 401)
        response.headers['Content-Type'] = 'application/json'
        return response


# logout user
@app.route('/logout/')
def logout():
    if 'username' in login_session:
        # reset variables
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return redirect(url_for('show_garage_sales'))
    else:
        flash("You were not logged in!")
        return redirect(url_for('show_garage_sales'))


def create_user():
    user = User(
        name=login_session['username'],
        email=login_session['email'],
        img_url=login_session['picture']
    )
    session.add(user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
