"""
NEXUS-AI Prediction Engine
Makes intelligent predictions about network behavior using trained AI models

This module loads trained machine learning models and uses them to analyze
network scan features and predict potential attack types or suspicious behavior.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from datetime import datetime


def load_enhanced_model(model_path=None, quiet=False):
    """
    Load the trained AI model for making predictions
    
    This function loads the ensemble model that combines multiple algorithms:
    - Random Forest for robust classification
    - Neural Network for complex pattern recognition
    - Preprocessing scaler for feature normalization
    
    Args:
        model_path (str, optional): Path to the model file. If None, uses default location.
        quiet (bool): If True, suppress loading messages
        
    Returns:
        dict: Loaded model containing all components needed for prediction
        
    Raises:
        FileNotFoundError: If model file doesn't exist
        ValueError: If model file is corrupted or invalid
    """
    # Try multiple possible model locations
    if model_path is None:
        possible_paths = [
            'models/model.pkl',
            'models/sample_model.pkl',
            os.path.join(os.path.dirname(__file__), '..', '..', '..', 'models', 'model.pkl'),
            os.path.join(os.path.dirname(__file__), '..', '..', '..', 'models', 'sample_model.pkl'),
            os.path.join(os.getcwd(), 'models', 'model.pkl'),
            os.path.join(os.getcwd(), 'models', 'sample_model.pkl')
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                model_path = path
                break
        else:
            raise FileNotFoundError(
                "No trained model found. Please run 'python scripts/training/create_sample_model.py' "
                "or 'python scripts/training/train_enhanced_ai.py' to create a model first."
            )
    
    try:
        # Load the model from disk
        if not quiet:
            print(f"🤖 Loading AI model from: {model_path}")
        ensemble_model = joblib.load(model_path)
        
        # Validate the loaded model structure
        if not isinstance(ensemble_model, dict):
            raise ValueError("Invalid model format: expected dictionary structure")
        
        required_keys = ['models', 'scaler', 'model_type']
        for key in required_keys:
            if key not in ensemble_model:
                raise ValueError(f"Invalid model: missing required key '{key}'")
        
        if not quiet:
            print("✅ AI model loaded successfully")
        return ensemble_model
        
    except Exception as e:
        raise ValueError(f"Failed to load model from {model_path}: {e}")


def predict_class(feature_vector, ensemble_model, quiet=False):
    """
    Make a prediction using the loaded AI model
    
    This function:
    1. Preprocesses the input features using the trained scaler
    2. Runs predictions through all models in the ensemble
    3. Combines results using voting or averaging
    4. Returns the most likely class prediction
    
    Args:
        feature_vector (numpy.ndarray): Input features from network scan
        ensemble_model (dict): Loaded ensemble model
        quiet (bool): If True, suppress prediction messages
        
    Returns:
        int: Predicted class index (0-4 for our 5 attack types)
        
    Raises:
        ValueError: If feature vector has wrong shape or model is invalid
    """
    try:
        # Validate input features
        if feature_vector is None or not hasattr(feature_vector, 'shape'):
            raise ValueError("Invalid feature vector: None or missing shape attribute")
        
        if len(feature_vector.shape) != 2:
            raise ValueError(f"Expected 2D feature vector, got shape {feature_vector.shape}")
        
        if feature_vector.shape[1] != 150:  # Expected feature count
            raise ValueError(
                f"Expected 150 features, got {feature_vector.shape[1]}. "
                "Make sure you're using the correct parser."
            )
        
        # Validate ensemble model structure
        if not isinstance(ensemble_model, dict):
            raise ValueError("Invalid ensemble model: expected dictionary")
        
        if 'scaler' not in ensemble_model:
            raise ValueError("Invalid ensemble model: missing scaler")
        
        if 'models' not in ensemble_model:
            raise ValueError("Invalid ensemble model: missing models")
        
        # Preprocess features using the trained scaler
        scaler = ensemble_model['scaler']
        scaled_features = scaler.transform(feature_vector)
        
        # Get predictions from all models in the ensemble
        model_predictions = []
        model_confidences = []
        
        for model_name, model in ensemble_model['models'].items():
            try:
                # Get prediction and confidence
                prediction = model.predict(scaled_features)[0]
                confidence_scores = model.predict_proba(scaled_features)[0]
                max_confidence = np.max(confidence_scores)
                
                model_predictions.append(prediction)
                model_confidences.append(max_confidence)
                
                if not quiet:
                    print(f"  📊 {model_name}: {prediction} (confidence: {max_confidence:.2f})")
            except Exception as model_error:
                if not quiet:
                    print(f"  ⚠️  {model_name}: Error - {model_error}")
                # Use default values for failed model
                model_predictions.append(0)
                model_confidences.append(0.25)
        
        # Ensure we have at least one prediction
        if not model_predictions:
            raise ValueError("No valid model predictions available")
        
        # Combine predictions using weighted voting
        final_prediction = combine_ensemble_predictions(
            model_predictions, 
            model_confidences
        )
        
        # Calculate average confidence
        avg_confidence = np.mean(model_confidences) if model_confidences else 0.5
        
        # Get label mapping
        label_mapping = get_label_mapping(ensemble_model)
        prediction_label = label_mapping.get(final_prediction, 'unknown')
        
        print(f"🎯 Final AI Prediction: {prediction_label} (confidence: {avg_confidence:.2f})")
        
        return {
            'class': prediction_label,
            'confidence': avg_confidence,
            'class_index': final_prediction
        }
        
    except Exception as e:
        raise ValueError(f"Prediction failed: {e}")


def combine_ensemble_predictions(predictions, confidences):
    """
    Combine multiple model predictions into a final result
    
    Uses weighted voting where each model's vote is weighted by its confidence.
    This gives more weight to models that are more certain about their prediction.
    
    Args:
        predictions (list): List of predictions from each model
        confidences (list): List of confidence scores from each model
        
    Returns:
        int: Final combined prediction
    """
    # Validate inputs
    if not predictions or not confidences:
        raise ValueError("Empty predictions or confidences list")
    
    if len(predictions) != len(confidences):
        raise ValueError("Mismatched predictions and confidences lengths")
    
    # Create weighted vote counts
    vote_counts = {}
    
    for prediction, confidence in zip(predictions, confidences):
        # Ensure prediction is valid
        if prediction is None:
            continue
            
        # Ensure confidence is valid
        if confidence is None or confidence < 0:
            confidence = 0.1  # Default minimum confidence
        
        if prediction not in vote_counts:
            vote_counts[prediction] = 0
        vote_counts[prediction] += confidence
    
    # If no valid votes, return default prediction
    if not vote_counts:
        return 0  # Default to first class
    
    # Return the prediction with highest weighted votes
    final_prediction = max(vote_counts.items(), key=lambda x: x[1])[0]
    
    return final_prediction


def get_model_info(ensemble_model=None):
    """Get information about the AI model with enhanced details"""
    try:
        if ensemble_model is None:
            # Try to load the model if not provided
            ensemble_model = load_enhanced_model()
            if ensemble_model is None:
                return {
                    'status': 'not_loaded',
                    'error': 'No model available',
                    'model_type': 'unknown',
                    'algorithms': [],
                    'accuracy': 0.0,
                    'last_updated': None
                }
        
        # Extract model information
        model_info = {
            'status': 'loaded',
            'model_type': 'ensemble',
            'algorithms': list(ensemble_model.keys()) if isinstance(ensemble_model, dict) else ['unknown'],
            'accuracy': 0.0,  # Would need to calculate from test data
            'last_updated': datetime.now().isoformat(),
            'total_models': len(ensemble_model) if isinstance(ensemble_model, dict) else 1
        }
        
        # Add algorithm-specific details
        if isinstance(ensemble_model, dict):
            for name, model in ensemble_model.items():
                if hasattr(model, 'score'):
                    model_info[f'{name}_score'] = getattr(model, 'score', 0.0)
        
        return model_info
        
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'model_type': 'unknown',
            'algorithms': [],
            'accuracy': 0.0,
            'last_updated': None
        }


def get_label_mapping(ensemble_model):
    """
    Get the mapping between prediction indices and human-readable labels
    
    This function provides the label mapping that was used during training.
    If no custom mapping is stored, it returns a default mapping.
    
    Args:
        ensemble_model (dict): Loaded ensemble model
        
    Returns:
        dict: Mapping from prediction indices to labels
    """
    # Try to get the label encoder from the model
    label_encoder = ensemble_model.get('label_encoder', None)
    
    if label_encoder is not None:
        return label_encoder
    
    # If no label encoder, return default mapping
    default_labels = ["normal", "dos", "exploits", "probe", "r2l"]
    return {i: label for i, label in enumerate(default_labels)}


def get_prediction_confidence(feature_vector, ensemble_model):
    """
    Get confidence scores for all possible predictions
    
    This function provides confidence scores for each possible class,
    which can be useful for understanding how certain the AI is about
    its prediction and for ranking alternative possibilities.
    
    Args:
        feature_vector (numpy.ndarray): Input features
        ensemble_model (dict): Loaded ensemble model
        
    Returns:
        dict: Confidence scores for each class
    """
    try:
        # Preprocess features
        scaler = ensemble_model['scaler']
        scaled_features = scaler.transform(feature_vector)
        
        # Get confidence scores from all models
        all_confidences = []
        
        for model in ensemble_model['models'].values():
            confidence_scores = model.predict_proba(scaled_features)[0]
            all_confidences.append(confidence_scores)
        
        # Average confidence scores across all models
        average_confidences = np.mean(all_confidences, axis=0)
        
        # Create result dictionary
        confidence_dict = {
            'prediction_confidence': float(np.max(average_confidences)),
            'all_confidences': average_confidences.tolist(),
            'model_count': len(ensemble_model['models'])
        }
        
        return confidence_dict
        
    except Exception as e:
        return {
            'prediction_confidence': 0.0,
            'all_confidences': [0.0] * 5,
            'model_count': 0,
            'error': str(e)
        }


def validate_model_compatibility(ensemble_model):
    """
    Validate that the loaded model is compatible with current code
    
    Checks that the model has the expected structure and components
    needed for making predictions. This helps catch issues early.
    
    Args:
        ensemble_model (dict): Loaded ensemble model
        
    Returns:
        bool: True if model is compatible, False otherwise
        
    Raises:
        ValueError: If model is incompatible with detailed error message
    """
    # Check required components
    required_components = ['models', 'scaler', 'model_type']
    for component in required_components:
        if component not in ensemble_model:
            raise ValueError(f"Model missing required component: {component}")
    
    # Check that models dictionary is not empty
    if not ensemble_model['models']:
        raise ValueError("Model has no trained algorithms")
    
    # Check that scaler is properly initialized
    if ensemble_model['scaler'] is None:
        raise ValueError("Model scaler is not initialized")
    
    # Check that all models are sklearn-compatible
    for model_name, model in ensemble_model['models'].items():
        if not hasattr(model, 'predict') or not hasattr(model, 'predict_proba'):
            raise ValueError(f"Model {model_name} is not a valid sklearn classifier")
    
    return True


def get_model_performance_metrics(ensemble_model):
    """
    Get performance metrics for the loaded model
    
    If the model was trained with performance tracking, this function
    returns accuracy, precision, recall, and other metrics.
    
    Args:
        ensemble_model (dict): Loaded ensemble model
        
    Returns:
        dict: Performance metrics if available, empty dict otherwise
    """
    return ensemble_model.get('performance_metrics', {})


def is_sample_model(ensemble_model):
    """
    Check if the loaded model is a sample/training model
    
    Sample models are created for immediate testing and may have
    lower accuracy than models trained on real datasets.
    
    Args:
        ensemble_model (dict): Loaded ensemble model
        
    Returns:
        bool: True if this is a sample model, False otherwise
    """
    return ensemble_model.get('sample_model', False)
