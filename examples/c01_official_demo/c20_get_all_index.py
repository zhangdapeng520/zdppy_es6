import es6
import env

env.load(".env")

es = es6.client.new_env()
print(es.indices.get_alias().keys())

for key in es.indices.get_alias().keys():
    print(key, type(key))
