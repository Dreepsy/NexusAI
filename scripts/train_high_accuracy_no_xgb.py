#!/usr/bin/env python3
"""
High-Accuracy NEXUS-AI Training (90%+ target) - No XGBoost Version
Comprehensive training with all advanced techniques except XGBoost
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, ExtraTreesClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.decomposition import PCA
import lightgbm as lgb
from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.under_sampling import RandomUnderSampler
from imblearn.combine import SMOTEENN
from imblearn.ensemble import BalancedRandomForestClassifier
import matplotlib.pyplot as plt
import seaborn as sns

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def load_and_preprocess_data():
    """Load and preprocess the sample data with advanced techniques"""
    print("📊 Loading and preprocessing data with advanced techniques...")
    
    # Load sample data
    train_path = "data/sample/KDDTrain+.txt"
    test_path = "data/sample/KDDTest+.txt"
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("❌ Sample data not found. Run scripts/download_datasets.py first.")
        return None, None, None, None, None, None
    
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

def advanced_feature_engineering(df):
    """Create advanced features for better accuracy"""
    print("🔧 Creating advanced features...")
    
    # 1. Protocol-specific features
    df['tcp_ratio'] = (df['protocol_type'] == 'tcp').astype(int)
    df['udp_ratio'] = (df['protocol_type'] == 'udp').astype(int)
    df['icmp_ratio'] = (df['protocol_type'] == 'icmp').astype(int)
    
    # 2. Service-specific features
    df['http_traffic'] = (df['service'] == 'http').astype(int)
    df['https_traffic'] = (df['service'] == 'https').astype(int)
    df['ftp_traffic'] = (df['service'] == 'ftp').astype(int)
    df['ssh_traffic'] = (df['service'] == 'ssh').astype(int)
    df['telnet_traffic'] = (df['service'] == 'telnet').astype(int)
    
    # 3. Statistical features
    df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
    df['packet_ratio'] = df['count'] / (df['srv_count'] + 1)
    df['total_bytes'] = df['src_bytes'] + df['dst_bytes']
    df['bytes_per_packet'] = df['total_bytes'] / (df['count'] + 1)
    
    # 4. Time-based features
    df['duration_log'] = np.log1p(df['duration'])
    df['bytes_log'] = np.log1p(df['total_bytes'])
    df['duration_sqrt'] = np.sqrt(df['duration'])
    
    # 5. Rate-based features
    df['error_rate_total'] = df['serror_rate'] + df['rerror_rate']
    df['srv_error_rate_total'] = df['srv_serror_rate'] + df['srv_rerror_rate']
    
    # 6. Connection features
    df['connection_density'] = df['count'] * df['srv_count']
    df['host_connection_ratio'] = df['dst_host_count'] / (df['dst_host_srv_count'] + 1)
    
    # 7. Security features
    df['security_events'] = df['num_failed_logins'] + df['num_compromised'] + df['num_root']
    df['file_operations'] = df['num_file_creations'] + df['num_access_files']
    df['shell_operations'] = df['num_shells'] + df['root_shell']
    
    # 8. Interaction features
    df['login_attempts'] = df['logged_in'] + df['is_host_login'] + df['is_guest_login']
    df['privilege_escalation'] = df['su_attempted'] + df['num_root']
    
    print(f"✅ Created {len([col for col in df.columns if col not in ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty']])} new features")
    return df

def handle_class_imbalance(X_train, y_train):
    """Handle class imbalance using advanced techniques"""
    print("⚖️  Handling class imbalance...")
    
    # Check class distribution
    unique, counts = np.unique(y_train, return_counts=True)
    print(f"   Original class distribution: {dict(zip(unique, counts))}")
    
    # Use SMOTE for oversampling
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
    
    # Check new distribution
    unique_balanced, counts_balanced = np.unique(y_train_balanced, return_counts=True)
    print(f"   Balanced class distribution: {dict(zip(unique_balanced, counts_balanced))}")
    
    return X_train_balanced, y_train_balanced

def feature_selection(X_train, y_train, X_test, n_features=50):
    """Perform advanced feature selection"""
    print("🎯 Performing feature selection...")
    
    # 1. Statistical feature selection
    selector = SelectKBest(score_func=f_classif, k=n_features)
    X_train_selected = selector.fit_transform(X_train, y_train)
    X_test_selected = selector.transform(X_test)
    
    # Get selected feature indices
    selected_features = selector.get_support()
    print(f"   Selected {np.sum(selected_features)} features out of {X_train.shape[1]}")
    
    return X_train_selected, X_test_selected, selector

def train_advanced_models(X_train, X_test, y_train, y_test):
    """Train advanced models with hyperparameter tuning"""
    print("🤖 Training advanced models with hyperparameter tuning...")
    
    models = {}
    
    # 1. LightGBM with class weights
    print("💡 Training LightGBM...")
    class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    lgb_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [6, 8, 10],
        'learning_rate': [0.1, 0.2, 0.3],
        'num_leaves': [31, 63, 127],
        'min_child_samples': [20, 50, 100]
    }
    
    lgb_model = GridSearchCV(
        lgb.LGBMClassifier(
            class_weight=dict(zip(np.unique(y_train), class_weights)),
            random_state=42,
            verbose=-1
        ),
        lgb_params,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    lgb_model.fit(X_train, y_train)
    models['lightgbm'] = lgb_model
    
    # 2. Balanced Random Forest
    print("🌲 Training Balanced Random Forest...")
    brf_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 15, 20],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    
    brf_model = GridSearchCV(
        BalancedRandomForestClassifier(random_state=42),
        brf_params,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    brf_model.fit(X_train, y_train)
    models['balanced_random_forest'] = brf_model
    
    # 3. Deep Neural Network with advanced architecture
    print("🧠 Training Deep Neural Network...")
    nn_model = MLPClassifier(
        hidden_layer_sizes=(256, 128, 64, 32),
        max_iter=1000,
        early_stopping=True,
        validation_fraction=0.1,
        alpha=0.001,
        learning_rate='adaptive',
        random_state=42
    )
    nn_model.fit(X_train, y_train)
    models['neural_network'] = nn_model
    
    # 4. Gradient Boosting
    print("📈 Training Gradient Boosting...")
    gb_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [6, 8, 10],
        'learning_rate': [0.1, 0.2, 0.3],
        'subsample': [0.8, 0.9, 1.0]
    }
    
    gb_model = GridSearchCV(
        GradientBoostingClassifier(random_state=42),
        gb_params,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    gb_model.fit(X_train, y_train)
    models['gradient_boosting'] = gb_model
    
    # 5. Extra Trees Classifier
    print("🌳 Training Extra Trees...")
    et_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 15, 20],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    
    et_model = GridSearchCV(
        ExtraTreesClassifier(random_state=42),
        et_params,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    et_model.fit(X_train, y_train)
    models['extra_trees'] = et_model
    
    # 6. Advanced Random Forest
    print("🌲 Training Advanced Random Forest...")
    rf_params = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 15, 20],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2', None]
    }
    
    rf_model = GridSearchCV(
        RandomForestClassifier(random_state=42, class_weight='balanced'),
        rf_params,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=0
    )
    rf_model.fit(X_train, y_train)
    models['advanced_random_forest'] = rf_model
    
    return models

def create_ensemble_model(models, X_train, y_train):
    """Create a voting ensemble for maximum accuracy"""
    print("🎯 Creating ensemble model...")
    
    # Create voting classifier
    estimators = []
    for name, model in models.items():
        estimators.append((name, model))
    
    ensemble = VotingClassifier(
        estimators=estimators,
        voting='soft',
        n_jobs=-1
    )
    
    # Train ensemble
    ensemble.fit(X_train, y_train)
    
    return ensemble

def evaluate_models(models, ensemble, X_test, y_test):
    """Comprehensive model evaluation"""
    print("📈 Evaluating models...")
    
    results = {}
    
    # Evaluate individual models
    for name, model in models.items():
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        
        results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
        
        print(f"   {name}: {accuracy:.4f} accuracy, {f1:.4f} F1-score")
    
    # Evaluate ensemble
    y_pred_ensemble = ensemble.predict(X_test)
    y_pred_proba_ensemble = ensemble.predict_proba(X_test)
    
    accuracy_ensemble = accuracy_score(y_test, y_pred_ensemble)
    precision_ensemble, recall_ensemble, f1_ensemble, _ = precision_recall_fscore_support(y_test, y_pred_ensemble, average='weighted')
    
    results['ensemble'] = {
        'accuracy': accuracy_ensemble,
        'precision': precision_ensemble,
        'recall': recall_ensemble,
        'f1_score': f1_ensemble,
        'predictions': y_pred_ensemble,
        'probabilities': y_pred_proba_ensemble
    }
    
    print(f"   Ensemble: {accuracy_ensemble:.4f} accuracy, {f1_ensemble:.4f} F1-score")
    
    return results

def save_high_accuracy_model(models, ensemble, scaler, le_label, feature_selector, results):
    """Save the high-accuracy model"""
    print("💾 Saving high-accuracy model...")
    
    # Create comprehensive model object
    high_accuracy_model = {
        'models': models,
        'ensemble': ensemble,
        'scaler': scaler,
        'label_encoder': le_label,
        'feature_selector': feature_selector,
        'model_type': 'high_accuracy_ensemble_no_xgb',
        'training_date': datetime.now().isoformat(),
        'sample_model': False,
        'feature_count': X_train.shape[1],
        'num_classes': len(le_label.classes_),
        'performance_metrics': results,
        'techniques_used': [
            'Advanced Feature Engineering',
            'Class Imbalance Handling (SMOTE)',
            'Feature Selection',
            'Hyperparameter Tuning',
            'Multiple Advanced Models (LightGBM, Balanced RF, Neural Network, Gradient Boosting, Extra Trees)',
            'Ensemble Voting'
        ]
    }
    
    # Save model
    model_path = "models/high_accuracy_model_no_xgb.pkl"
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(high_accuracy_model, model_path)
    
    print(f"✅ High-accuracy model saved to {model_path}")
    print(f"   Size: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")
    
    return high_accuracy_model

def create_advanced_performance_report(results, le_label, y_test, output_dir="reports"):
    """Create advanced performance visualizations"""
    print("📊 Creating advanced performance report...")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Model comparison chart
    model_names = list(results.keys())
    accuracies = [results[name]['accuracy'] for name in model_names]
    f1_scores = [results[name]['f1_score'] for name in model_names]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Accuracy comparison
    colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E', '#BC4749', '#8B5A96']
    bars1 = ax1.bar(model_names, accuracies, color=colors[:len(model_names)])
    ax1.set_title('Model Accuracy Comparison (No XGBoost)')
    ax1.set_ylabel('Accuracy')
    ax1.set_ylim(0, 1)
    for bar, acc in zip(bars1, accuracies):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{acc:.3f}', ha='center', va='bottom')
    
    # F1-score comparison
    bars2 = ax2.bar(model_names, f1_scores, color=colors[:len(model_names)])
    ax2.set_title('Model F1-Score Comparison (No XGBoost)')
    ax2.set_ylabel('F1-Score')
    ax2.set_ylim(0, 1)
    for bar, f1 in zip(bars2, f1_scores):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{f1:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/advanced_model_comparison_no_xgb.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Confusion matrix for best model
    best_model_name = max(results.keys(), key=lambda x: results[x]['accuracy'])
    best_predictions = results[best_model_name]['predictions']
    
    cm = confusion_matrix(y_test, best_predictions)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=le_label.classes_,
                yticklabels=le_label.classes_)
    plt.title(f'Confusion Matrix - {best_model_name.title()} (No XGBoost)')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(f'{output_dir}/advanced_confusion_matrix_no_xgb.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✅ Advanced performance report saved to {output_dir}/")

def main():
    """Main high-accuracy training function"""
    print("🚀 NEXUS-AI High-Accuracy Training (No XGBoost)")
    print("="*60)
    
    # Load and preprocess data
    train_df, test_df, columns = load_and_preprocess_data()
    if train_df is None:
        return
    
    # Advanced feature engineering
    train_df = advanced_feature_engineering(train_df)
    test_df = advanced_feature_engineering(test_df)
    
    # Combine for preprocessing
    combined_df = pd.concat([train_df, test_df], ignore_index=True)
    
    # Encode categorical features
    le_protocol = LabelEncoder()
    le_service = LabelEncoder()
    le_flag = LabelEncoder()
    le_label = LabelEncoder()
    
    combined_df['protocol_type'] = le_protocol.fit_transform(combined_df['protocol_type'])
    combined_df['service'] = le_service.fit_transform(combined_df['service'])
    combined_df['flag'] = le_flag.fit_transform(combined_df['flag'])
    combined_df['label'] = le_label.fit_transform(combined_df['label'])
    
    # Split back
    train_size = len(train_df)
    train_processed = combined_df[:train_size]
    test_processed = combined_df[train_size:]
    
    # Prepare features
    feature_columns = [col for col in train_processed.columns if col not in ['label', 'difficulty']]
    
    X_train = train_processed[feature_columns].values
    y_train = train_processed['label'].values
    X_test = test_processed[feature_columns].values
    y_test = test_processed['label'].values
    
    # Advanced scaling
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"✅ Preprocessed data: {X_train_scaled.shape[1]} features")
    
    # Handle class imbalance
    X_train_balanced, y_train_balanced = handle_class_imbalance(X_train_scaled, y_train)
    
    # Feature selection
    X_train_selected, X_test_selected, feature_selector = feature_selection(X_train_balanced, y_train_balanced, X_test_scaled)
    
    # Train advanced models
    models = train_advanced_models(X_train_selected, X_test_selected, y_train_balanced, y_test)
    
    # Create ensemble
    ensemble = create_ensemble_model(models, X_train_selected, y_train_balanced)
    
    # Evaluate models
    results = evaluate_models(models, ensemble, X_test_selected, y_test)
    
    # Save high-accuracy model
    high_accuracy_model = save_high_accuracy_model(models, ensemble, scaler, le_label, feature_selector, results)
    
    # Create advanced performance report
    create_advanced_performance_report(results, le_label, y_test)
    
    # Print summary
    print("\n" + "="*60)
    print("🎉 High-Accuracy Training Completed!")
    print("="*60)
    
    print(f"\n📊 Model Performance:")
    for name, result in results.items():
        print(f"   {name}: {result['accuracy']:.4f} accuracy, {result['f1_score']:.4f} F1-score")
    
    best_model = max(results.keys(), key=lambda x: results[x]['accuracy'])
    print(f"\n🏆 Best Model: {best_model} ({results[best_model]['accuracy']:.4f} accuracy)")
    
    print(f"\n📁 Files created:")
    print(f"   Model: models/high_accuracy_model_no_xgb.pkl")
    print(f"   Reports: reports/advanced_model_comparison_no_xgb.png")
    print(f"   Reports: reports/advanced_confusion_matrix_no_xgb.png")
    
    print(f"\n🔧 Techniques Applied:")
    for technique in high_accuracy_model['techniques_used']:
        print(f"   ✅ {technique}")
    
    print(f"\n🎯 Next Steps:")
    print(f"   1. Test the model: python scripts/test_high_accuracy_model.py")
    print(f"   2. Use CLI: python -m src.nexus.cli.commands --help")
    print(f"   3. Train with real data for 95%+ accuracy")

if __name__ == "__main__":
    main() 