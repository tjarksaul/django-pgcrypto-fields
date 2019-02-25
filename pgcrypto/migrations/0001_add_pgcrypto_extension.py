from django.db import migrations


CREATE_EXTENSION = 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
DROP_EXTENSION = 'DROP EXTENSION pgcrypto;'
CREATE_REDIS = 'CREATE EXTENSION IF NOT EXISTS redis_fdw;'
CREATE_REDIS_SERVER = 'CREATE SERVER IF NOT EXISTS redis_server FOREIGN DATA WRAPPER redis_fdw ' \
                      'OPTIONS (address \'redis\', port \'6379\');'
CREATE_REDIS_TABLE = 'CREATE FOREIGN TABLE IF NOT EXISTS key_store (id text, key text) ' \
                     'SERVER redis_server OPTIONS (database \'0\');'
CREATE_REDIS_USER = 'CREATE USER MAPPING IF NOT EXISTS FOR PUBLIC SERVER redis_server;'


class Migration(migrations.Migration):

    dependencies = []

    operations = [
        migrations.RunSQL([CREATE_EXTENSION, CREATE_REDIS, CREATE_REDIS_SERVER, CREATE_REDIS_TABLE, CREATE_REDIS_USER],
                          DROP_EXTENSION),
    ]
