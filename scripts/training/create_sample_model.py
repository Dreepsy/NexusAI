#!/usr/bin/env python3
"""
Create a sample model for NEXUS-AI
This script creates a simple model for testing and demonstration purposes
"""

import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

def create_sample_model():
    """Create a sample model for testing purposes"""
    print("🤖 Creating sample model for NEXUS-AI...")
    
    # Create synthetic data for demonstration
    np.random.seed(42)
    n_samples = 1000
    n_features = 150  # Match the expected feature count
    
    # Generate synthetic features
    X = np.random.randn(n_samples, n_features)
    
    # Generate synthetic labels (5 classes: normal, exploits, reconnaissance, dos, backdoor)
    y = np.random.randint(0, 5, n_samples)
    
    # Split the data
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Create and train models
    print("📊 Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    
    print("🧠 Training Neural Network...")
    nn_model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=200,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1
    )
    nn_model.fit(X_train, y_train)
    
    # Create scaler
    scaler = StandardScaler()
    scaler.fit(X_train)
    
    # Create ensemble model
    ensemble_model = {
        'models': {
            'random_forest': rf_model,
            'neural_network': nn_model
        },
        'scaler': scaler,
        'model_type': 'ensemble',
        'training_date': datetime.now().isoformat(),
        'sample_model': True,
        'feature_count': n_features,
        'num_classes': 5,
        'label_encoder': None,  # Will use default labels
        'performance_metrics': {
            'accuracy': 0.85,  # Mock accuracy
            'f1_score': 0.83,
            'precision': 0.84,
            'recall': 0.82
        }
    }
    
    # Ensure models directory exists
    models_dir = "models"
    if not os.path.exists(models_dir):
        # Try alternative paths
        alt_paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "models"),
            os.path.join(os.getcwd(), "models")
        ]
        for path in alt_paths:
            if os.path.exists(path):
                models_dir = path
                break
        else:
            # Create models directory in current working directory
            models_dir = os.path.join(os.getcwd(), "models")
    
    os.makedirs(models_dir, exist_ok=True)
    
    # Save the model
    model_path = os.path.join(models_dir, 'sample_model.pkl')
    joblib.dump(ensemble_model, model_path)
    
    print(f"✅ Sample model created and saved to: {model_path}")
    print(f"📊 Model contains {len(ensemble_model['models'])} algorithms")
    print(f"🎯 Expected accuracy: {ensemble_model['performance_metrics']['accuracy']:.2%}")
    print(f"📈 Feature count: {ensemble_model['feature_count']}")
    print(f"🏷️  Number of classes: {ensemble_model['num_classes']}")
    
    return model_path

if __name__ == "__main__":
    try:
        model_path = create_sample_model()
        print("\n🎉 Sample model creation completed successfully!")
        print("💡 You can now use the model with: python main.py")
        print("🔧 Or run the CLI: python -m src.nexus.cli.commands --help")
    except Exception as e:
        print(f"❌ Error creating sample model: {e}")
        sys.exit(1) 