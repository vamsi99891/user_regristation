from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING

client = AsyncIOMotorClient("mongodb+srv://vamsikota3545:OaND13njPjqJtZyC@resumestore.av7rqbr.mongodb.net/")
db = client["userregristation"]
users_collection = db["register"]
blacklist_collection = db["blacklisted_tokens"]

blacklist_collection.create_index(
    [("expires_at", ASCENDING)],
    expireAfterSeconds=0  
)