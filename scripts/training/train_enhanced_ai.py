#!/usr/bin/env python3
"""
Enhanced AI Training Script for NEXUS-AI
Trains ensemble models with multiple datasets for network security analysis
"""

import os
import sys
import yaml
import numpy as np
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

def main():
    """Main training function"""
    print("🚀 NEXUS-AI Enhanced Training System")
    print("=" * 50)
    print(f"Training started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.yaml')
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Check dataset availability
    dataset_configs = config.get('datasets', [])
    missing_datasets = []
    
    for ds_config in dataset_configs:
        train_path = ds_config['train']
        test_path = ds_config['test']
        
        if not os.path.exists(train_path):
            missing_datasets.append(f"Training file: {train_path}")
        if not os.path.exists(test_path):
            missing_datasets.append(f"Test file: {test_path}")
    
    if missing_datasets:
        print("❌ Missing dataset files:")
        for missing in missing_datasets:
            print(f"   - {missing}")
        print("\n💡 Download datasets:")
        print("   - NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html")
        print("   - UNSW-NB15: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/")
        print("   - Place files in 'data/' directory")
        return
    
    print("✅ All dataset files found!")
    
    # Run training
    try:
        from nexus.core.main import main as train_main
        train_main()
        
        print("\n🎉 Training completed successfully!")
        print("📁 Models saved in 'models/' directory")
        
        # Show model information
        print("\n📊 Model Information:")
        try:
            from nexus.cli.predictor import get_model_info
            model_info = get_model_info()
            print(f"   Model Type: {model_info['model_type']}")
            print(f"   Number of Models: {model_info['num_models']}")
            print(f"   Model Names: {', '.join(model_info['model_names'])}")
            print(f"   Feature Count: {model_info['feature_count']}")
        except Exception as e:
            print(f"   Could not load model info: {e}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Install dependencies: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Training failed: {e}")

def create_sample_data():
    """Create sample data for testing"""
    print("📝 Creating sample data files...")
    
    os.makedirs('data', exist_ok=True)
    
    # NSL-KDD columns
    columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root",
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
    ]
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 1000
    
    # Normal traffic
    normal_data = []
    for i in range(n_samples // 2):
        row = [
            np.random.uniform(0, 100),  # duration
            np.random.choice(['tcp', 'udp']),  # protocol_type
            np.random.choice(['http', 'ftp', 'ssh']),  # service
            np.random.choice(['SF', 'S0', 'REJ']),  # flag
            np.random.uniform(0, 1000),  # src_bytes
            np.random.uniform(0, 1000),  # dst_bytes
            np.random.randint(0, 2),  # land
            np.random.randint(0, 2),  # wrong_fragment
            np.random.randint(0, 2),  # urgent
            np.random.randint(0, 2),  # hot
            np.random.randint(0, 2),  # num_failed_logins
            np.random.randint(0, 2),  # logged_in
            np.random.randint(0, 2),  # num_compromised
            np.random.randint(0, 2),  # root_shell
            np.random.randint(0, 2),  # su_attempted
            np.random.randint(0, 2),  # num_root
            np.random.randint(0, 2),  # num_file_creations
            np.random.randint(0, 2),  # num_shells
            np.random.randint(0, 2),  # num_access_files
            np.random.randint(0, 2),  # num_outbound_cmds
            np.random.randint(0, 2),  # is_host_login
            np.random.randint(0, 2),  # is_guest_login
            np.random.randint(0, 10),  # count
            np.random.randint(0, 10),  # srv_count
            np.random.uniform(0, 1),  # serror_rate
            np.random.uniform(0, 1),  # srv_serror_rate
            np.random.uniform(0, 1),  # rerror_rate
            np.random.uniform(0, 1),  # srv_rerror_rate
            np.random.uniform(0, 1),  # same_srv_rate
            np.random.uniform(0, 1),  # diff_srv_rate
            np.random.uniform(0, 1),  # srv_diff_host_rate
            np.random.randint(0, 10),  # dst_host_count
            np.random.randint(0, 10),  # dst_host_srv_count
            np.random.uniform(0, 1),  # dst_host_same_srv_rate
            np.random.uniform(0, 1),  # dst_host_diff_srv_rate
            np.random.uniform(0, 1),  # dst_host_same_src_port_rate
            np.random.uniform(0, 1),  # dst_host_srv_diff_host_rate
            np.random.uniform(0, 1),  # dst_host_serror_rate
            np.random.uniform(0, 1),  # dst_host_srv_serror_rate
            np.random.uniform(0, 1),  # dst_host_rerror_rate
            np.random.uniform(0, 1),  # dst_host_srv_rerror_rate
            'normal',  # label
            np.random.randint(1, 5)  # difficulty
        ]
        normal_data.append(row)
    
    # Attack traffic
    attack_data = []
    for i in range(n_samples // 2):
        row = [
            np.random.uniform(0, 100),  # duration
            np.random.choice(['tcp', 'udp']),  # protocol_type
            np.random.choice(['http', 'ftp', 'ssh']),  # service
            np.random.choice(['SF', 'S0', 'REJ']),  # flag
            np.random.uniform(1000, 10000),  # src_bytes
            np.random.uniform(1000, 10000),  # dst_bytes
            np.random.randint(0, 2),  # land
            np.random.randint(0, 2),  # wrong_fragment
            np.random.randint(0, 2),  # urgent
            np.random.randint(0, 2),  # hot
            np.random.randint(2, 10),  # num_failed_logins
            np.random.randint(0, 2),  # logged_in
            np.random.randint(2, 10),  # num_compromised
            np.random.randint(0, 2),  # root_shell
            np.random.randint(0, 2),  # su_attempted
            np.random.randint(0, 2),  # num_root
            np.random.randint(0, 2),  # num_file_creations
            np.random.randint(0, 2),  # num_shells
            np.random.randint(0, 2),  # num_access_files
            np.random.randint(0, 2),  # num_outbound_cmds
            np.random.randint(0, 2),  # is_host_login
            np.random.randint(0, 2),  # is_guest_login
            np.random.randint(10, 100),  # count
            np.random.randint(10, 100),  # srv_count
            np.random.uniform(0.5, 1),  # serror_rate
            np.random.uniform(0.5, 1),  # srv_serror_rate
            np.random.uniform(0.5, 1),  # rerror_rate
            np.random.uniform(0.5, 1),  # srv_rerror_rate
            np.random.uniform(0, 0.5),  # same_srv_rate
            np.random.uniform(0.5, 1),  # diff_srv_rate
            np.random.uniform(0.5, 1),  # srv_diff_host_rate
            np.random.randint(10, 100),  # dst_host_count
            np.random.randint(10, 100),  # dst_host_srv_count
            np.random.uniform(0, 0.5),  # dst_host_same_srv_rate
            np.random.uniform(0.5, 1),  # dst_host_diff_srv_rate
            np.random.uniform(0, 0.5),  # dst_host_same_src_port_rate
            np.random.uniform(0.5, 1),  # dst_host_srv_diff_host_rate
            np.random.uniform(0.5, 1),  # dst_host_serror_rate
            np.random.uniform(0.5, 1),  # dst_host_srv_serror_rate
            np.random.uniform(0.5, 1),  # dst_host_rerror_rate
            np.random.uniform(0.5, 1),  # dst_host_srv_rerror_rate
            np.random.choice(['neptune', 'satan', 'ipsweep']),  # label
            np.random.randint(1, 5)  # difficulty
        ]
        attack_data.append(row)
    
    # Combine and shuffle
    all_data = normal_data + attack_data
    np.random.shuffle(all_data)
    
    # Split into train/test
    train_data = all_data[:int(len(all_data) * 0.8)]
    test_data = all_data[int(len(all_data) * 0.8):]
    
    # Save to files
    import csv
    
    with open('data/KDDTrain+.txt', 'w', newline='') as f:
        writer = csv.writer(f)
        for row in train_data:
            writer.writerow(row)
    
    with open('data/KDDTest+.txt', 'w', newline='') as f:
        writer = csv.writer(f)
        for row in test_data:
            writer.writerow(row)
    
    print("✅ Created sample NSL-KDD data files")
    print("   - data/KDDTrain+.txt")
    print("   - data/KDDTest+.txt")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--create-sample-data":
        create_sample_data()
    else:
        main() 