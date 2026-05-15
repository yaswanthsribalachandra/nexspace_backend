from pymongo import MongoClient

from config import settings

client = MongoClient(
    settings.mongo_uri
)

db = client["linkmanager"]

# Collections
users_collection = db["users"]

links_collection = db["links"]

otp_collection = db["otp"]