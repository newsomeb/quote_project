from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from extensions import db
from models import Collection, Quote, quote_collection
from flask import Blueprint

collections_bp = Blueprint('collections', __name__)


@collections_bp.route('/create_collection', methods=['GET', 'POST'])
@login_required
def create_collection():
    quote_id = request.args.get('quote_id')
    existing_collections = Collection.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        new_collection = Collection(name=name, description=description, user=current_user, public=True)

        # Associate quote with the new collection if quote_id is provided
        if quote_id:
            quote = Quote.query.get_or_404(quote_id)
            new_collection.quotes.append(quote)

        db.session.add(new_collection)
        db.session.commit()

        flash('Collection created successfully!', 'success')
        return redirect(url_for('collections.my_collections'))

    return render_template('create_collection.html', existing_collections=existing_collections)


@collections_bp.route('/my_collections')
@login_required
def my_collections():
    user_collections = Collection.query.filter_by(user_id=current_user.id).all()
    return render_template('my_collections.html', user_collections=user_collections)


@collections_bp.route('/collection/<int:collection_id>', methods=['GET'])
def view_collection(collection_id):
    collection = Collection.query.get_or_404(collection_id)

    # Fetch all quotes belonging to the specified collection
    quotes_in_collection = Quote.query.join(quote_collection).filter(
        quote_collection.c.collection_id == collection_id).all()

    return render_template('view_collection.html', collection=collection, quotes=quotes_in_collection)


@collections_bp.route('/add_to_collection', methods=['POST'])
@login_required
def add_to_collection():
    quote_id = validate_id(request.form.get('quote_id'))
    collection_id = request.form.get('collection_id')

    if collection_id == 'new':
        return redirect(url_for('collections.create_collection', quote_id=quote_id))

    if not quote_id or not validate_collection_access(collection_id):
        return redirect(url_for('main.home'))

    collection = get_collection(collection_id)
    quote = Quote.query.get_or_404(quote_id)

    collection.quotes.append(quote)
    try:
        db.session.commit()
        flash('Quote added to collection successfully!', 'success')
        return redirect(url_for('collections.view_collection', collection_id=collection.id))
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding quote to collection: {str(e)}", "danger")
        return redirect(url_for('main.home'))


@collections_bp.route('/delete_collection/<int:collection_id>', methods=['POST'])
@login_required
def delete_collection(collection_id):
    collection = Collection.query.get_or_404(collection_id)

    if collection.user_id != current_user.id:
        flash('Access denied!', 'danger')
        return redirect(url_for('main.home'))

    try:
        db.session.delete(collection)
        db.session.commit()
        flash('Collection deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting collection: {str(e)}", "danger")

    return redirect(url_for('collections.my_collections'))


@collections_bp.route('/remove_quote/<int:collection_id>/<int:quote_id>', methods=['POST'])
@login_required
def remove_quote_from_collection(collection_id, quote_id):
    if not validate_id(quote_id) or not validate_collection_access(collection_id):
        return redirect(url_for('main.home'))

    collection = Collection.query.get_or_404(collection_id)
    quote = Quote.query.get_or_404(quote_id)

    # Remove quote if it exists in the collection
    if quote in collection.quotes:
        collection.quotes.remove(quote)
        db.session.commit()
        flash('Quote removed from the collection successfully!', 'success')
    else:
        flash('Quote not found in the collection!', 'danger')

    return redirect(url_for('collections.view_collection', collection_id=collection_id))


@collections_bp.route('/public_collections')
def public_collections():
    public_collections = Collection.query.filter_by(public=True).all()
    return render_template('public_collections.html', collections=public_collections)


@collections_bp.route('/update_privacy/<int:collection_id>', methods=['POST'])
@login_required
def update_privacy(collection_id):
    if not validate_collection_access(collection_id):
        return redirect(url_for('main.home'))

    collection = Collection.query.get_or_404(collection_id)
    new_privacy_status = request.form.get('public') == 'on'

    # Only update if there is a change in privacy status
    if collection.public != new_privacy_status:
        collection.public = new_privacy_status
        try:
            db.session.commit()
            flash('Privacy status updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating privacy status: {str(e)}", "danger")

    return redirect(url_for('collections.my_collections'))


@collections_bp.route('/browse_collections', methods=['GET'])
@login_required
def browse_collections():
    # Fetch collections that are either public or belong to other users
    other_collections = Collection.query.filter(
        (Collection.user_id != current_user.id) & (Collection.public == True)).all()
    return render_template('browse_collections.html', collections=other_collections)


def validate_id(id):
    try:
        return int(id)
    except ValueError:
        flash('Invalid ID.', 'danger')
        return None


def validate_collection_access(collection_id):
    if not validate_id(collection_id) or Collection.query.get(collection_id).user_id != current_user.id:
        flash('Access denied!', 'danger')
        return False
    return True


def get_collection(collection_id):
    return current_user.collections.first() if collection_id == 0 else Collection.query.get(collection_id)

@collections_bp.route('/add_to_favorites/<int:quote_id>', methods=['POST'])
@login_required
def add_to_favorites(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    favorites = Collection.query.filter_by(user_id=current_user.id, is_favorite=True).first()

    if quote not in favorites.quotes:
        favorites.quotes.append(quote)
        try:
            db.session.commit()
            flash('Quote added to Favorites successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding quote to Favorites: {str(e)}", "danger")

    return redirect(url_for('collections.view_collection', collection_id=favorites.id))
