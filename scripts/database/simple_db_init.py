#!/usr/bin/env python3
"""
Simple database initialization script
Creates the SQLite database with proper schema
"""

import sqlite3
import os
from pathlib import Path

def create_database():
    """Create the enhanced exploit database with proper schema"""
    
    # Ensure data directory exists
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)
    
    db_path = data_dir / 'exploits.db'
    
    print(f"🔧 Creating database at: {db_path}")
    
    # Remove existing database if it exists
    if db_path.exists():
        db_path.unlink()
        print("🗑️  Removed existing database")
    
    # Create new database with enhanced schema
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create exploits table with enhanced schema
    cursor.execute('''
        CREATE TABLE exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            service TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            difficulty TEXT,
            risk_level TEXT,
            code TEXT,
            requirements TEXT,
            usage_instructions TEXT,
            safety_warnings TEXT,
            created_date TEXT,
            updated_date TEXT,
            verified BOOLEAN DEFAULT FALSE,
            tags TEXT,
            hash TEXT UNIQUE,
            version INTEGER DEFAULT 1
        )
    ''')
    
    # Create vulnerability_mappings table
    cursor.execute('''
        CREATE TABLE vulnerability_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            service TEXT,
            version_pattern TEXT,
            exploit_id INTEGER,
            FOREIGN KEY (exploit_id) REFERENCES exploits (id) ON DELETE CASCADE
        )
    ''')
    
    # Create exploit_metadata table
    cursor.execute('''
        CREATE TABLE exploit_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploit_id INTEGER,
            key TEXT,
            value TEXT,
            FOREIGN KEY (exploit_id) REFERENCES exploits (id) ON DELETE CASCADE
        )
    ''')
    
    # Create exploit_versions table for versioning
    cursor.execute('''
        CREATE TABLE exploit_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploit_id INTEGER,
            version INTEGER,
            code TEXT,
            changes TEXT,
            created_date TEXT,
            FOREIGN KEY (exploit_id) REFERENCES exploits (id) ON DELETE CASCADE
        )
    ''')
    
    # Create indexes for better performance
    cursor.execute('CREATE INDEX idx_exploits_service ON exploits(service)')
    cursor.execute('CREATE INDEX idx_exploits_category ON exploits(category)')
    cursor.execute('CREATE INDEX idx_exploits_difficulty ON exploits(difficulty)')
    cursor.execute('CREATE INDEX idx_exploits_risk_level ON exploits(risk_level)')
    cursor.execute('CREATE INDEX idx_exploits_verified ON exploits(verified)')
    cursor.execute('CREATE INDEX idx_exploits_hash ON exploits(hash)')
    cursor.execute('CREATE INDEX idx_vuln_mappings_cve ON vulnerability_mappings(cve_id)')
    cursor.execute('CREATE INDEX idx_vuln_mappings_service ON vulnerability_mappings(service)')
    
    conn.commit()
    conn.close()
    
    print("✅ Database created successfully!")
    
    # Verify the database was created
    if db_path.exists():
        print(f"📊 Database size: {db_path.stat().st_size} bytes")
        
        # Test database connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"📋 Created tables: {[table[0] for table in tables]}")
        conn.close()
        
        return True
    else:
        print("❌ Database creation failed")
        return False

def add_sample_exploits():
    """Add some sample educational exploits"""
    
    db_path = Path('data/exploits.db')
    if not db_path.exists():
        print("❌ Database not found")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Sample educational exploits
    sample_exploits = [
        {
            'name': 'Educational SSH Testing',
            'service': 'ssh',
            'category': 'authentication',
            'description': 'Educational SSH credential testing for authorized penetration testing',
            'difficulty': 'easy',
            'risk_level': 'medium',
            'code': '#!/usr/bin/env python3\nprint("Educational SSH testing tool")',
            'requirements': 'paramiko library',
            'usage_instructions': 'Use for educational purposes only',
            'safety_warnings': 'Only test on systems you own',
            'tags': 'ssh,educational,authentication',
            'hash': 'sample_hash_1'
        },
        {
            'name': 'Educational MySQL Testing',
            'service': 'mysql',
            'category': 'database',
            'description': 'Educational MySQL authentication testing',
            'difficulty': 'medium',
            'risk_level': 'high',
            'code': '#!/usr/bin/env python3\nprint("Educational MySQL testing tool")',
            'requirements': 'mysql-connector-python',
            'usage_instructions': 'Educational database testing',
            'safety_warnings': 'Only test on authorized systems',
            'tags': 'mysql,database,authentication',
            'hash': 'sample_hash_2'
        },
        {
            'name': 'Educational HTTP Testing',
            'service': 'http',
            'category': 'web_application',
            'description': 'Educational HTTP vulnerability testing',
            'difficulty': 'medium',
            'risk_level': 'high',
            'code': '#!/usr/bin/env python3\nprint("Educational HTTP testing tool")',
            'requirements': 'requests library',
            'usage_instructions': 'Test for web vulnerabilities',
            'safety_warnings': 'Only test on authorized web servers',
            'tags': 'http,web,educational',
            'hash': 'sample_hash_3'
        }
    ]
    
    for exploit in sample_exploits:
        cursor.execute('''
            INSERT INTO exploits (
                name, service, category, description, difficulty,
                risk_level, code, requirements, usage_instructions,
                safety_warnings, created_date, updated_date, verified, tags, hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            exploit['name'],
            exploit['service'],
            exploit['category'],
            exploit['description'],
            exploit['difficulty'],
            exploit['risk_level'],
            exploit['code'],
            exploit['requirements'],
            exploit['usage_instructions'],
            exploit['safety_warnings'],
            '2024-01-01T00:00:00',
            '2024-01-01T00:00:00',
            True,
            exploit['tags'],
            exploit['hash']
        ))
    
    conn.commit()
    conn.close()
    
    print(f"✅ Added {len(sample_exploits)} sample exploits")
    return True

def main():
    print("🚀 Simple Database Initialization")
    print("=" * 40)
    
    # Create database
    if create_database():
        # Add sample exploits
        add_sample_exploits()
        
        print("\n🎉 Database initialization completed successfully!")
        print("📁 Database location: data/exploits.db")
        print("💡 You can now use: nexusai --exploit-db")
    else:
        print("\n❌ Database initialization failed")

if __name__ == "__main__":
    main()
