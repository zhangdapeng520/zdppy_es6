import es6
import env

env.load(".env")

es = es6.client.new_env()

print(es.indices.get_mapping(index="shop_order"))
