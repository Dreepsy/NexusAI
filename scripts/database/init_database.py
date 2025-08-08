#!/usr/bin/env python3
"""
Initialize the enhanced exploit database with proper schema
"""

import sys
import os
sys.path.append('src')

from nexus.ai.exploit_database_enhanced import enhanced_exploit_db

def main():
    print("🔧 Initializing Enhanced Exploit Database...")
    
    try:
        # Force database initialization
        print("📊 Creating database with enhanced schema...")
        
        # Check if database was created successfully
        if enhanced_exploit_db.db_path.exists():
            print(f"✅ Database created at: {enhanced_exploit_db.db_path}")
            
            # Test database operations
            stats = enhanced_exploit_db.get_statistics()
            print(f"📈 Database statistics: {stats}")
            
            print("✅ Enhanced database initialized successfully!")
            return True
        else:
            print("❌ Database creation failed")
            return False
            
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return False

if __name__ == "__main__":
    main()
