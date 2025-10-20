import unittest
import requests
import json
import jwt
import sqlite3
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import threading
import subprocess
import sys

# Configuration
BASE_URL = "http://localhost:8080"
DB_FILE = "totally_not_my_privateKeys.db"


class TestJWKSServer(unittest.TestCase):
    """Test suite for JWKS server"""
    
    @classmethod
    def setUpClass(cls):
        """Start the server before running tests"""
        # Clean up any existing database
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        
        # Start the server in a separate process
        cls.server_process = subprocess.Popen(
            [sys.executable, "main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start
        time.sleep(2)
        
        # Verify server is running
        max_retries = 5
        for i in range(max_retries):
            try:
                response = requests.get(f"{BASE_URL}/.well-known/jwks.json", timeout=2)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                if i == max_retries - 1:
                    cls.tearDownClass()
                    raise Exception("Server failed to start")
                time.sleep(1)
    
    @classmethod
    def tearDownClass(cls):
        """Stop the server after all tests"""
        cls.server_process.terminate()
        cls.server_process.wait(timeout=5)
        
        # Clean up database
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
    
    def test_jwks_endpoint_returns_200(self):
        """Test that JWKS endpoint returns 200 status"""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
    
    def test_jwks_endpoint_returns_json(self):
        """Test that JWKS endpoint returns valid JSON"""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.headers.get("Content-type"), "application/json")
        
        # Verify it's valid JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_jwks_contains_keys_array(self):
        """Test that JWKS response contains 'keys' array"""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        data = response.json()
        
        self.assertIn("keys", data)
        self.assertIsInstance(data["keys"], list)
        self.assertGreater(len(data["keys"]), 0)
    
    def test_jwks_key_structure(self):
        """Test that JWKS keys have correct structure"""
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        data = response.json()
        
        key = data["keys"][0]
        required_fields = ["alg", "kty", "use", "kid", "n", "e"]
        
        for field in required_fields:
            self.assertIn(field, key)
        
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["kid"], "goodKID")
    
    def test_auth_endpoint_returns_jwt(self):
        """Test that /auth endpoint returns a JWT token"""
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        
        token = response.text
        # JWT should have 3 parts separated by dots
        parts = token.split('.')
        self.assertEqual(len(parts), 3)
    
    def test_auth_token_can_be_decoded(self):
        """Test that the JWT token can be decoded"""
        response = requests.post(f"{BASE_URL}/auth")
        token = response.text
        
        # Decode without verification first to check structure
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        self.assertIn("user", unverified)
        self.assertIn("exp", unverified)
        self.assertEqual(unverified["user"], "username")
    
    def test_auth_token_has_correct_kid(self):
        """Test that JWT token has correct kid in header"""
        response = requests.post(f"{BASE_URL}/auth")
        token = response.text
        
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["kid"], "goodKID")
    
    def test_auth_token_verification_with_jwks(self):
        """Test that JWT token can be verified using JWKS"""
        # Get the token
        auth_response = requests.post(f"{BASE_URL}/auth")
        token = auth_response.text
        
        # Get JWKS
        jwks_response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        jwks = jwks_response.json()
        
        # Extract public key from JWKS
        key_data = jwks["keys"][0]
        
        # Convert JWK to PEM format for verification
        n = int.from_bytes(
            base64.urlsafe_b64decode(key_data["n"] + "=="),
            byteorder='big'
        )
        e = int.from_bytes(
            base64.urlsafe_b64decode(key_data["e"] + "=="),
            byteorder='big'
        )
        
        from cryptography.hazmat.primitives.asymmetric import rsa
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())
        
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Verify token
        try:
            decoded = jwt.decode(token, pem, algorithms=["RS256"])
            self.assertEqual(decoded["user"], "username")
        except jwt.InvalidTokenError:
            self.fail("Token verification failed")
    
    def test_expired_token_parameter(self):
        """Test that expired parameter returns expired token"""
        response = requests.post(f"{BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        
        token = response.text
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["kid"], "expiredKID")
        
        # Decode and check expiration
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn("exp", decoded)
    
    def test_unsupported_methods_jwks(self):
        """Test that JWKS endpoint rejects unsupported methods"""
        unsupported_methods = [
            requests.post,
            requests.put,
            requests.delete,
            requests.patch,
            requests.head
        ]
        
        for method in unsupported_methods:
            response = method(f"{BASE_URL}/.well-known/jwks.json")
            self.assertEqual(response.status_code, 405)
    
    def test_unsupported_methods_auth(self):
        """Test that /auth endpoint rejects unsupported methods"""
        unsupported_methods = [
            requests.get,
            requests.put,
            requests.delete,
            requests.patch,
            requests.head
        ]
        
        for method in unsupported_methods:
            response = method(f"{BASE_URL}/auth")
            self.assertEqual(response.status_code, 405)
    
    def test_database_initialization(self):
        """Test that database is created and initialized"""
        self.assertTrue(os.path.exists(DB_FILE))
        
        # Connect and verify structure
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if keys table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        
        # Check table structure
        cursor.execute("PRAGMA table_info(keys)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        self.assertIn("kid", column_names)
        self.assertIn("key", column_names)
        self.assertIn("exp", column_names)
        
        conn.close()
    
    def test_database_contains_keys(self):
        """Test that database contains at least one key"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        
        self.assertGreater(count, 0)
        conn.close()
    
    def test_invalid_endpoint(self):
        """Test that invalid endpoints return 405"""
        response = requests.get(f"{BASE_URL}/invalid")
        self.assertEqual(response.status_code, 405)
    
    def test_token_expiration_time(self):
        """Test that non-expired token has future expiration"""
        response = requests.post(f"{BASE_URL}/auth")
        token = response.text
        
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp_time = decoded["exp"]
        
        import time
        current_time = time.time()
        
        # Token should expire in the future
        self.assertGreater(exp_time, current_time)


class TestDatabaseFunctions(unittest.TestCase):
    """Test database-related functionality"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = "test_keys.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        
        self.conn = sqlite3.connect(self.test_db)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS keys
                              (kid INTEGER PRIMARY KEY AUTOINCREMENT, 
                               key BLOB NOT NULL, 
                               exp INTEGER NOT NULL)''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up test database"""
        self.conn.close()
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
    
    def test_key_insertion(self):
        """Test that keys can be inserted into database"""
        test_key = b"test_key_data"
        test_exp = 1234567890
        
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                           (test_key, test_exp))
        self.conn.commit()
        
        self.cursor.execute("SELECT key, exp FROM keys WHERE kid = 1")
        row = self.cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[0], test_key)
        self.assertEqual(row[1], test_exp)
    
    def test_auto_increment_kid(self):
        """Test that kid auto-increments"""
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                           (b"key1", 100))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                           (b"key2", 200))
        self.conn.commit()
        
        self.cursor.execute("SELECT kid FROM keys ORDER BY kid")
        kids = [row[0] for row in self.cursor.fetchall()]
        
        self.assertEqual(kids, [1, 2])


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)