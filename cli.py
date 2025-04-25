import click
from flask import current_app
from . import db

@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    with current_app.open_resource('schema.sql') as f:
        connection = db.connect()
        with connection.cursor() as cursor:
            sql_script = f.read().decode('utf8')
    
            queries = [q.strip() for q in sql_script.split(';') if q.strip()]
            
            for query in queries:
                if query: 
                    cursor.execute(query)

        connection.commit()
    click.echo('Initialized the database.')