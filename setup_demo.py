#!/usr/bin/env python3
"""
Setup script to create demo accounts in MongoDB
Run this script to populate the database with demo users for testing
"""

from database import users_collection
from auth import hash_password
from datetime import datetime

DEMO_USERS = [
    {
        "email": "demo@example.com",
        "password": "Demo@123456",
        "full_name": "Demo User"
    },
    {
        "email": "test@example.com",
        "password": "Test@123456",
        "full_name": "Test User"
    }
]

def setup_demo_accounts():
    """Create demo accounts in MongoDB"""
    print("🔧 Setting up demo accounts...")
    
    for user_data in DEMO_USERS:
        # Check if user already exists
        existing = users_collection.find_one({"email": user_data["email"]})
        if existing:
            print(f"✅ User {user_data['email']} already exists")
            continue
        
        # Create new user
        hashed_password = hash_password(user_data["password"])
        user_doc = {
            "email": user_data["email"],
            "password": hashed_password,
            "full_name": user_data["full_name"],
            "created_at": datetime.utcnow()
        }
        
        result = users_collection.insert_one(user_doc)
        print(f"✨ Created user {user_data['email']} (ID: {result.inserted_id})")
    
    print("\n✅ Demo setup complete!")
    print("\n📝 You can now login with:")
    for user in DEMO_USERS:
        print(f"   Email: {user['email']}")
        print(f"   Password: {user['password']}\n")

if __name__ == "__main__":
    setup_demo_accounts()
