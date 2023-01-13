`psql -h [DB ID].us-east-1.rds.amazonaws.com -U [DBUSER] -d [DBNAME]`


create synapse db in remote postgres shell:
```
CREATE ROLE "synapse" WITH LOGIN PASSWORD '[LONG STRING PASSWORD]';
CREATE DATABASE "synapse" ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' template=template0 OWNER synapse;
```
