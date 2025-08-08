import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GridSearchCV
from .preprocessing import load_multiple_datasets, AdvancedDatasetLoader
from .config import get_config, get_logger
import joblib
import warnings
warnings.filterwarnings('ignore')

# Get configuration and logger
config = get_config()
logger = get_logger()

# Try to import SHAP for explainability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

# Try to import deep learning libraries
try:
    import tensorflow as tf
    from tensorflow import keras
    DEEP_LEARNING_AVAILABLE = True
except ImportError:
    DEEP_LEARNING_AVAILABLE = False

# Get model path and parameters from config
MODEL_PATH = config.get_path('paths.models')
MODEL_PARAMS = config.get('model', {})
DATASET_CONFIGS = config.get('datasets', [])


class EnhancedAITrainer:
    """
    Enhanced AI trainer that can handle multiple datasets and multiple model types.
    Supports ensemble methods, deep learning, and advanced training techniques.
    """
    
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.feature_names = []
        self.dataset_loader = AdvancedDatasetLoader()
        logger.info("EnhancedAITrainer initialized")
        
    def load_and_prepare_data(self, dataset_configs):
        """
        Load and prepare multiple datasets with advanced preprocessing.
        """
        logger.info("Loading and preparing multiple datasets")
        
        # Load all datasets
        all_datasets = {}
        for ds_config in dataset_configs:
            logger.info(f"Loading dataset: {ds_config['type']}")
            X, y, feature_names = self.dataset_loader.load_dataset(
                ds_config['type'],
                ds_config['train'],
                ds_config['test'],
                binary_classification=False
            )
            all_datasets[ds_config['type']] = {
                'X': X,
                'y': y,
                'feature_names': feature_names
            }
        
        # Combine datasets intelligently
        combined_data = self._combine_datasets_intelligently(all_datasets)
        
        logger.info(f"Combined dataset shape: {combined_data['X'].shape}")
        logger.info(f"Number of classes: {len(np.unique(combined_data['y']))}")
        logger.info(f"Feature count: {combined_data['X'].shape[1]}")
        
        return combined_data
    
    def _combine_datasets_intelligently(self, all_datasets):
        """
        Intelligently combine multiple datasets with proper feature alignment.
        """
        # Find the maximum number of features across all datasets
        max_features = max(X.shape[1] for data in all_datasets.values() for X in [data['X']])
        
        combined_X = []
        combined_y = []
        combined_feature_names = []
        
        for dataset_name, data in all_datasets.items():
            X = data['X']
            y = data['y']
            
            # Pad features to match the maximum
            if X.shape[1] < max_features:
                padding = np.zeros((X.shape[0], max_features - X.shape[1]))
                X = np.hstack([X, padding])
            
            combined_X.append(X)
            combined_y.append(y)
            
            # Extend feature names
            if not combined_feature_names:
                combined_feature_names = data['feature_names']
                if len(combined_feature_names) < max_features:
                    combined_feature_names.extend([f'pad_{i}' for i in range(max_features - len(combined_feature_names))])
        
        # Combine all data
        X_combined = np.vstack(combined_X)
        y_combined = np.hstack(combined_y)
        
        # Normalize features
        scaler = StandardScaler()
        X_combined = scaler.fit_transform(X_combined)
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_combined = label_encoder.fit_transform(y_combined)
        
        return {
            'X': X_combined,
            'y': y_combined,
            'feature_names': combined_feature_names,
            'scaler': scaler,
            'label_encoder': label_encoder
        }
    
    def train_ensemble_models(self, X_train, y_train):
        """
        Train multiple models and create an ensemble.
        """
        logger.info("Training ensemble of AI models")
        
        models = {}
        
        # 1. Enhanced Neural Network
        logger.info("Training Enhanced Neural Network...")
        nn_model = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            max_iter=500,
            learning_rate='adaptive',
            early_stopping=True,
            validation_fraction=0.1,
            random_state=42,
            alpha=0.001
        )
        nn_model.fit(X_train, y_train)
        models['neural_network'] = nn_model
        
        # 2. Random Forest
        logger.info("Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train, y_train)
        models['random_forest'] = rf_model
        
        # 3. Gradient Boosting
        logger.info("Training Gradient Boosting...")
        gb_model = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=8,
            random_state=42
        )
        gb_model.fit(X_train, y_train)
        models['gradient_boosting'] = gb_model
        
        # 4. Deep Learning Model (if available)
        if DEEP_LEARNING_AVAILABLE:
            logger.info("Training Deep Learning Model...")
            dl_model = self._create_deep_learning_model(X_train.shape[1], len(np.unique(y_train)))
            dl_model.fit(X_train, y_train, epochs=50, batch_size=32, validation_split=0.2, verbose=0)
            models['deep_learning'] = dl_model
        
        return models
    
    def _create_deep_learning_model(self, input_dim, num_classes):
        """
        Create a deep learning model using TensorFlow/Keras.
        """
        model = keras.Sequential([
            keras.layers.Dense(256, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def evaluate_models(self, models, X_test, y_test):
        """
        Evaluate all models and return comprehensive results.
        """
        logger.info("Evaluating all models")
        
        results = {}
        for name, model in models.items():
            logger.info(f"\nEvaluating {name}...")
            
            if name == 'deep_learning':
                # Deep learning model prediction
                y_pred_proba = model.predict(X_test)
                y_pred = np.argmax(y_pred_proba, axis=1)
            else:
                # Scikit-learn model prediction
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average='weighted')
            
            results[name] = {
                'accuracy': accuracy,
                'f1_score': f1,
                'predictions': y_pred,
                'probabilities': y_pred_proba,
                'classification_report': classification_report(y_test, y_pred)
            }
            
            logger.info(f"Completed {name} - Accuracy: {accuracy:.4f}, F1-Score: {f1:.4f}")
        
        return results
    
    def create_ensemble_predictor(self, models, weights=None):
        """
        Create an ensemble predictor that combines all models.
        """
        if weights is None:
            weights = {name: 1.0 for name in models.keys()}
        
        def ensemble_predict(X):
            predictions = []
            for name, model in models.items():
                if name == 'deep_learning':
                    pred_proba = model.predict(X)
                else:
                    pred_proba = model.predict_proba(X)
                predictions.append(pred_proba * weights[name])
            
            # Average predictions
            ensemble_proba = np.mean(predictions, axis=0)
            return np.argmax(ensemble_proba, axis=1)
        
        return ensemble_predictor
    
    def save_models(self, models, scaler, label_encoder, feature_names):
        """
        Save all models and preprocessing components.
        """
        logger.info("Saving all models and components")
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        os.makedirs("models/", exist_ok=True)
        
        # Save individual models
        for name, model in models.items():
            model_path = f"models/{name}_model.pkl"
            joblib.dump(model, model_path)
            logger.info(f"Saved {name} to {model_path}")
        
        # Save preprocessing components
        joblib.dump(scaler, "models/scaler.pkl")
        joblib.dump(label_encoder, "models/label_encoder.pkl")
        joblib.dump(feature_names, "models/feature_names.pkl")
        
        # Save ensemble
        ensemble = {
            'models': models,
            'scaler': scaler,
            'label_encoder': label_encoder,
            'feature_names': feature_names
        }
        joblib.dump(ensemble, MODEL_PATH)
        logger.info(f"Saved ensemble model to {MODEL_PATH}")
    
    def explain_model(self, model, X_test, feature_names):
        """
        Generate model explanations using SHAP.
        """
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available for model explanation")
            return
        
        logger.info("Generating model explanations")
        
        try:
            # Use TreeExplainer for tree-based models
            if hasattr(model, 'estimators_'):
                explainer = shap.TreeExplainer(model)
            else:
                # Use KernelExplainer for other models
                explainer = shap.KernelExplainer(model.predict_proba, X_test[:100])
            
            shap_values = explainer.shap_values(X_test[:10])
            
            # Print feature importance
            if isinstance(shap_values, list):
                shap_values = shap_values[0]
            
            feature_importance = np.abs(shap_values).mean(0)
            top_features = np.argsort(feature_importance)[::-1][:10]
            
            logger.info("Top 10 most important features:")
            for i, idx in enumerate(top_features):
                feature_name = feature_names[idx] if idx < len(feature_names) else f"Feature_{idx}"
                logger.info(f"  {i+1}. {feature_name}: {feature_importance[idx]:.4f}")
                
        except Exception as e:
            logger.warning(f"Could not generate explanations: {e}")


def main():
    """
    Enhanced main function with multi-dataset training and evaluation.
    """
    logger.info("NEXUS-AI Enhanced Training System")
    logger.info("=" * 50)
    
    # Initialize enhanced trainer
    trainer = EnhancedAITrainer(config)
    
    # Load and prepare data
    combined_data = trainer.load_and_prepare_data(DATASET_CONFIGS)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        combined_data['X'], 
        combined_data['y'], 
        test_size=0.2, 
        random_state=42,
        stratify=combined_data['y']
    )
    
    logger.info(f"Training set: {X_train.shape[0]} samples")
    logger.info(f"Test set: {X_test.shape[0]} samples")
    
    # Train ensemble models
    models = trainer.train_ensemble_models(X_train, y_train)
    
    # Evaluate models
    results = trainer.evaluate_models(models, X_test, y_test)
    
    # Create and evaluate ensemble
    ensemble_predictor = trainer.create_ensemble_predictor(models)
    ensemble_predictions = ensemble_predictor(X_test)
    ensemble_accuracy = accuracy_score(y_test, ensemble_predictions)
    ensemble_f1 = f1_score(y_test, ensemble_predictions, average='weighted')
    
    logger.info(f"\nEnsemble Results:")
    logger.info(f"   Accuracy: {ensemble_accuracy:.4f}")
    logger.info(f"   F1-Score: {ensemble_f1:.4f}")
    
    # Save models
    trainer.save_models(models, combined_data['scaler'], combined_data['label_encoder'], combined_data['feature_names'])
    
    # Explain best model
    best_model_name = max(results.keys(), key=lambda x: results[x]['accuracy'])
    best_model = models[best_model_name]
    trainer.explain_model(best_model, X_test, combined_data['feature_names'])
    
    logger.info("\nTraining completed successfully!")
    logger.info("Models saved in 'models/' directory")
    logger.info("Ready for production use!")


if __name__ == "__main__":
    main()