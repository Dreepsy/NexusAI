#!/usr/bin/env python3
"""
Train NEXUS-AI with Sample Data
Custom training script for the sample dataset
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def load_sample_data():
    """Load the sample dataset"""
    print("📊 Loading sample data...")
    
    # Load training data
    train_path = "data/sample/KDDTrain+.txt"
    test_path = "data/sample/KDDTest+.txt"
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("❌ Sample data not found. Run scripts/download_datasets.py first.")
        return None, None, None, None
    
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
    
    # Load data
    train_df = pd.read_csv(train_path, header=None, names=columns)
    test_df = pd.read_csv(test_path, header=None, names=columns)
    
    print(f"✅ Loaded {len(train_df)} training samples and {len(test_df)} test samples")
    
    return train_df, test_df, columns

def preprocess_data(train_df, test_df):
    """Preprocess the data for training"""
    print("🔧 Preprocessing data...")
    
    # Combine train and test for preprocessing
    combined_df = pd.concat([train_df, test_df], ignore_index=True)
    
    # Encode categorical features
    le_protocol = LabelEncoder()
    le_service = LabelEncoder()
    le_flag = LabelEncoder()
    le_label = LabelEncoder()
    
    # Fit encoders on combined data
    combined_df['protocol_type'] = le_protocol.fit_transform(combined_df['protocol_type'])
    combined_df['service'] = le_service.fit_transform(combined_df['service'])
    combined_df['flag'] = le_flag.fit_transform(combined_df['flag'])
    combined_df['label'] = le_label.fit_transform(combined_df['label'])
    
    # Split back into train and test
    train_size = len(train_df)
    train_processed = combined_df[:train_size]
    test_processed = combined_df[train_size:]
    
    # Prepare features and labels
    feature_columns = [col for col in train_processed.columns if col not in ['label', 'difficulty']]
    
    X_train = train_processed[feature_columns].values
    y_train = train_processed['label'].values
    X_test = test_processed[feature_columns].values
    y_test = test_processed['label'].values
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"✅ Preprocessed data: {X_train_scaled.shape[1]} features")
    print(f"   Training samples: {len(X_train_scaled)}")
    print(f"   Test samples: {len(X_test_scaled)}")
    print(f"   Classes: {len(np.unique(y_train))}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, le_label

def train_models(X_train, X_test, y_train, y_test):
    """Train multiple models"""
    print("🤖 Training AI models...")
    
    models = {}
    
    # 1. Random Forest
    print("📊 Training Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    models['random_forest'] = rf_model
    
    # 2. Neural Network
    print("🧠 Training Neural Network...")
    nn_model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=200,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1
    )
    nn_model.fit(X_train, y_train)
    models['neural_network'] = nn_model
    
    return models

def evaluate_models(models, X_test, y_test, le_label):
    """Evaluate model performance"""
    print("📈 Evaluating models...")
    
    results = {}
    
    for name, model in models.items():
        # Make predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        results[name] = {
            'accuracy': accuracy,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
        
        print(f"   {name}: {accuracy:.4f} accuracy")
    
    return results

def create_ensemble_model(models, scaler, le_label, results, feature_count):
    """Create ensemble model"""
    print("🎯 Creating ensemble model...")
    
    ensemble_model = {
        'models': models,
        'scaler': scaler,
        'label_encoder': le_label,
        'model_type': 'ensemble',
        'training_date': datetime.now().isoformat(),
        'sample_model': False,
        'feature_count': feature_count,
        'num_classes': len(le_label.classes_),
        'performance_metrics': {
            'accuracy': np.mean([r['accuracy'] for r in results.values()]),
            'individual_accuracies': {name: r['accuracy'] for name, r in results.items()}
        }
    }
    
    return ensemble_model

def save_model(ensemble_model, model_path):
    """Save the trained model"""
    print(f"💾 Saving model to {model_path}...")
    
    # Ensure models directory exists
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save model
    joblib.dump(ensemble_model, model_path)
    
    print(f"✅ Model saved successfully!")
    print(f"   Location: {model_path}")
    print(f"   Size: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")

def create_performance_report(results, le_label, y_test, output_dir="reports"):
    """Create performance visualization"""
    print("📊 Creating performance report...")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Create confusion matrix for best model
    best_model_name = max(results.keys(), key=lambda x: results[x]['accuracy'])
    best_predictions = results[best_model_name]['predictions']
    
    # Create confusion matrix
    cm = confusion_matrix(y_test, best_predictions)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=le_label.classes_,
                yticklabels=le_label.classes_)
    plt.title(f'Confusion Matrix - {best_model_name.title()}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(f'{output_dir}/confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    # Create accuracy comparison
    model_names = list(results.keys())
    accuracies = [results[name]['accuracy'] for name in model_names]
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(model_names, accuracies, color=['#2E86AB', '#A23B72', '#F18F01'])
    plt.title('Model Accuracy Comparison')
    plt.ylabel('Accuracy')
    plt.ylim(0, 1)
    
    # Add value labels on bars
    for bar, acc in zip(bars, accuracies):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{acc:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/accuracy_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Performance report saved to {output_dir}/")

def main():
    """Main training function"""
    print("🚀 NEXUS-AI Training with Sample Data")
    print("="*60)
    
    # Load data
    train_df, test_df, columns = load_sample_data()
    if train_df is None:
        return
    
    # Preprocess data
    X_train, X_test, y_train, y_test, scaler, le_label = preprocess_data(train_df, test_df)
    
    # Train models
    models = train_models(X_train, X_test, y_train, y_test)
    
    # Evaluate models
    results = evaluate_models(models, X_test, y_test, le_label)
    
    # Create ensemble
    ensemble_model = create_ensemble_model(models, scaler, le_label, results, X_train.shape[1])
    
    # Save model
    model_path = "models/enhanced_model.pkl"
    save_model(ensemble_model, model_path)
    
    # Create performance report
    create_performance_report(results, le_label, y_test)
    
    # Print summary
    print("\n" + "="*60)
    print("🎉 Training completed successfully!")
    print("="*60)
    
    print(f"\n📊 Model Performance:")
    for name, result in results.items():
        print(f"   {name}: {result['accuracy']:.4f} accuracy")
    
    print(f"\n📁 Files created:")
    print(f"   Model: {model_path}")
    print(f"   Reports: reports/confusion_matrix.png")
    print(f"   Reports: reports/accuracy_comparison.png")
    
    print(f"\n🎯 Next steps:")
    print(f"   1. Test the model: python -m src.nexus.cli.commands --help")
    print(f"   2. Analyze a scan: python -m src.nexus.cli.commands --input your_scan.xml")
    print(f"   3. View reports: open reports/")

if __name__ == "__main__":
    main() 