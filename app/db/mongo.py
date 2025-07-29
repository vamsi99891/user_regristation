from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING

client = AsyncIOMotorClient("mongodb+srv://vamsikota3545:<db_password>@resumestore.av7rqbr.mongodb.net/")
db = client["user_registration_model"]
users_collection = db["users"]
blacklist_collection = db["blacklisted_tokens"]

blacklist_collection.create_index(
    [("expires_at", ASCENDING)],
    expireAfterSeconds=0  
)