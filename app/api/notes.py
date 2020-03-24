from flask import jsonify, request, g, url_for, current_app
from .. import db
from ..models import Note
from . import api
from .errors import forbidden

@api.route('/notes/')
def get_posts():
    page = request.args.get('page', 1, type=int)
    pagination = Note.query.paginate(
        page, per_page=current_app.config['NOTIFY_NOTES_PER_PAGE'],
        error_out=False)
    notes = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('api.get_notes', page=page-1)
    next = None
    if pagination.has_next:
        next = url_for('api.get_notes', page=page+1)
    return jsonify({
        'notes': [note.to_json() for note in notes],
        'prev': prev,
        'next': next,
        'count': pagination.total
    })


@api.route('/notes/<int:id>')
def get_post(id):
    note = Note.query.get_or_404(id)
    return jsonify(note.to_json())


@api.route('/notes/', methods=['POST'])
def new_note():
    note = Note.from_json(request.json)
    note.author = g.current_user
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_json()), 201, \
        {'Location': url_for('api.get_note', id=note.id)}


@api.route('/notes/<int:id>', methods=['PUT'])
def edit_note(id):
    note = Note.query.get_or_404(id)
    if g.current_user != note.author:
        return forbidden('Insufficient permissions')
    note.title = request.json.get('title', note.title)
    note.content = request.json.get('content', note.body)
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_json())
