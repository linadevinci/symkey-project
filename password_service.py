from key_service import KeyManagementService
import argon2
import secrets
import json
import time
import base64
from dataclasses import dataclass, asdict
from typing import Optional, Dict

@dataclass
class User:
    username: str
    hashed_password: str
    salt: str
    encrypted_hash: str
    created_at: float

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

class PasswordManager:
    def __init__(self, key_service: KeyManagementService, user_file="users.json"):
        self.key_service = key_service
        self.user_file = user_file
        self.users: Dict[str, User] = {}
        self.failed_attempts = {}
        self._load_users()

        # Argon2 settings
        self.time_cost = 3
        self.memory_cost = 65536
        self.parallelism = 4
        self.hash_len = 32

    def _load_users(self):
        try:
            with open(self.user_file, 'r') as f:
                data = json.load(f)
                self.users = {
                    username: User.from_dict(user_data)
                    for username, user_data in data.items()
                }
        except FileNotFoundError:
            self.users = {}

    def _save_users(self):
        with open(self.user_file, 'w') as f:
            json.dump({
                username: user.to_dict()
                for username, user in self.users.items()
            }, f)

    def register_user(self, username: str, password: str) -> dict:
        if not username or len(username) < 3:
            return {
                "success": False,
                "message": "Username must be at least 3 characters long"
            }
        
        if username in self.users:
            return {
                "success": False,
                "message": "This username is already taken. Please choose another one."
            }
        
        # Password validation
        if len(password) < 12:
            return {
                "success": False,
                "message": "Password must be at least 12 characters long"
            }
        
        if not any(c.isupper() for c in password):
            return {
                "success": False,
                "message": "Password must contain at least one uppercase letter"
            }
        
        if not any(c.islower() for c in password):
            return {
                "success": False,
                "message": "Password must contain at least one lowercase letter"
            }
        
        if not any(c.isdigit() for c in password):
            return {
                "success": False,
                "message": "Password must contain at least one number"
            }
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return {
                "success": False,
                "message": "Password must contain at least one special character"
            }
        
        # If all validations pass, proceed with registration
        salt = secrets.token_hex(16)
        hasher = argon2.PasswordHasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len
        )
        
        hashed_password = hasher.hash(password + salt)
        
        # Encrypt the hash and encode as base64
        encrypted_bytes = self.key_service.encrypt(hashed_password.encode())
        encrypted_hash = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        user = User(
            username=username,
            hashed_password=hashed_password,
            salt=salt,
            encrypted_hash=encrypted_hash,
            created_at=time.time()
        )
        
        self.users[username] = user
        self._save_users()
        return {
            "success": True,
            "message": "Account created successfully! You can now log in."
        }
    
    def verify_password(self, username: str, password: str) -> dict:
        if not username:
            return {
                "success": False,
                "message": "Please enter a username"
            }
        
        if not password:
            return {
                "success": False,
                "message": "Please enter a password"
            }
        
        if username not in self.users:
            return {
                "success": False,
                "message": "Username not found. Please check your spelling or register for an account."
            }
        
        user = self.users[username]
        hasher = argon2.PasswordHasher()
        
        try:
            hasher.verify(user.hashed_password, password + user.salt)
            
            # Verify hash hasn't been tampered with by decrypting stored hash
            encrypted_bytes = base64.b64decode(user.encrypted_hash)
            decrypted_hash = self.key_service.decrypt(encrypted_bytes).decode()
            
            if decrypted_hash != user.hashed_password:
                return {
                    "success": False,
                    "message": "Security Alert: Your account may have been compromised. Please contact support."
                }
            
            return {
                "success": True,
                "message": "Login successful! Welcome back, " + username
            }
            
        except argon2.exceptions.VerifyMismatchError:
            return {
                "success": False,
                "message": "Incorrect password. Please try again."
            }