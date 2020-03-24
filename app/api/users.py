from flask import jsonify, request, current_app, url_for
from . import api
from ..models import User, Note

@api.route('/users/<int:id>')
def get_user(id):
    user = User.query.get_or_404(id)
    return jsonify(user.to_json())


@api.route('/users/<int:id>/notes/')
def get_user_notes(id):
    user = User.query.get_or_404(id)
    page = request.args.get('page', 1, type=int)
    pagination = user.notes.order_by(Note.timestamp.desc()).paginate(
        page, per_page=current_app.config['NOTIFY_NOTES_PER_PAGE'],
        error_out=False)
    notes = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('api.get_user_notes', id=id, page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('api.get_user_notes', id=id, page=page+1)
    return jsonify({
        'notes': [post.to_json() for note in notes],
        'prev': prev,
        'next': next,
        'count': pagination.total
    })
