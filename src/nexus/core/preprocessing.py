import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE, ADASYN
from pydantic import BaseModel, ValidationError, validator
from typing import List, Dict, Tuple, Optional
import os
import warnings
warnings.filterwarnings('ignore')

# --- Data validation schemas ---
class NSLKDDRow(BaseModel):
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    land: int
    wrong_fragment: int
    urgent: int
    hot: int
    num_failed_logins: int
    logged_in: int
    num_compromised: int
    root_shell: int
    su_attempted: int
    num_root: int
    num_file_creations: int
    num_shells: int
    num_access_files: int
    num_outbound_cmds: int
    is_host_login: int
    is_guest_login: int
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float
    label: str
    difficulty: int

    @validator('protocol_type', 'service', 'flag', 'label')
    def not_empty(cls, v):
        if not v:
            raise ValueError('Field cannot be empty')
        return v

class UNSWNB15Row(BaseModel):
    # Only validate a subset of columns for brevity
    id: int
    dur: float
    proto: str
    service: str
    state: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    sttl: int
    attack_cat: str
    label: int

    @validator('proto', 'service', 'state', 'attack_cat')
    def not_empty(cls, v):
        if not v:
            raise ValueError('Field cannot be empty')
        return v


class AdvancedDatasetLoader:
    """
    Advanced dataset loader that can handle multiple datasets with intelligent preprocessing.
    Supports data validation, feature engineering, and advanced balancing techniques.
    """
    
    def __init__(self):
        self.dataset_processors = {
            'nsl_kdd': self._process_nsl_kdd,
            'unsw_nb15': self._process_unsw_nb15,
            'custom': self._process_custom_dataset
        }
        self.feature_engineering_enabled = True
        self.advanced_balancing = True
    
    def load_dataset(self, dataset_type: str, train_path: str, test_path: str, 
                    binary_classification: bool = False) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Load and process a dataset with advanced preprocessing.
        
        Args:
            dataset_type: Type of dataset ('nsl_kdd', 'unsw_nb15', 'custom')
            train_path: Path to training data
            test_path: Path to test data
            binary_classification: Whether to use binary classification
            
        Returns:
            X: Feature matrix
            y: Target labels
            feature_names: List of feature names
        """
        print(f"📊 Loading {dataset_type} dataset...")
        
        if dataset_type not in self.dataset_processors:
            raise ValueError(f"Unsupported dataset type: {dataset_type}")
        
        # Process the dataset
        X, y, feature_names = self.dataset_processors[dataset_type](
            train_path, test_path, binary_classification
        )
        
        # Apply advanced preprocessing
        X, y, feature_names = self._apply_advanced_preprocessing(X, y, feature_names)
        
        print(f"✅ Loaded {dataset_type}: {X.shape[0]} samples, {X.shape[1]} features")
        return X, y, feature_names
    
    def _process_nsl_kdd(self, train_path: str, test_path: str, binary_classification: bool) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Process NSL-KDD dataset with enhanced preprocessing."""
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
        df_train = pd.read_csv(train_path, names=columns)
        df_test = pd.read_csv(test_path, names=columns)
        df = pd.concat([df_train, df_test])
        
        # Data validation
        self._validate_nsl_kdd(df)
        
        # Remove difficulty column
        df.drop(columns=["difficulty"], inplace=True)
        
        # Handle labels
        if binary_classification:
            df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
        else:
            le = LabelEncoder()
            df["label"] = le.fit_transform(df["label"])
        
        # Feature engineering
        if self.feature_engineering_enabled:
            df = self._engineer_nsl_kdd_features(df)
        
        # One-hot encoding
        categorical_cols = ["protocol_type", "service", "flag"]
        df = pd.get_dummies(df, columns=categorical_cols)
        
        # Extract features and labels
        X = df.drop(columns=["label"]).values
        y = df["label"].values
        feature_names = df.drop(columns=["label"]).columns.tolist()
        
        return X, y, feature_names
    
    def _process_unsw_nb15(self, train_path: str, test_path: str, binary_classification: bool) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Process UNSW-NB15 dataset with enhanced preprocessing."""
        # Load data
        df1 = pd.read_csv(train_path)
        df2 = pd.read_csv(test_path)
        df = pd.concat([df1, df2])
        
        # Data validation
        self._validate_unsw_nb15(df)
        
        # Handle labels
        if binary_classification:
            df['label'] = df['attack_cat'].apply(lambda x: 0 if x == 'Normal' else 1)
        else:
            le = LabelEncoder()
            df['label'] = le.fit_transform(df['attack_cat'])
        
        # Remove unnecessary columns
        df.drop(columns=["id", "attack_cat"], inplace=True)
        
        # Feature engineering
        if self.feature_engineering_enabled:
            df = self._engineer_unsw_nb15_features(df)
        
        # One-hot encoding for categorical variables
        categorical_cols = df.select_dtypes(include=['object']).columns
        df = pd.get_dummies(df, columns=categorical_cols)
        
        # Extract features and labels
        X = df.drop(columns=["label"]).values
        y = df["label"].values
        feature_names = df.drop(columns=["label"]).columns.tolist()
        
        return X, y, feature_names
    
    def _process_custom_dataset(self, train_path: str, test_path: str, binary_classification: bool) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Process custom dataset with flexible preprocessing."""
        # Load data
        df_train = pd.read_csv(train_path)
        df_test = pd.read_csv(test_path)
        df = pd.concat([df_train, df_test])
        
        # Assume last column is the label
        label_col = df.columns[-1]
        
        # Handle labels
        if binary_classification:
            # Assume binary classification
            unique_labels = df[label_col].unique()
            df['label'] = df[label_col].apply(lambda x: 0 if x == unique_labels[0] else 1)
        else:
            le = LabelEncoder()
            df['label'] = le.fit_transform(df[label_col])
        
        # Remove original label column
        df.drop(columns=[label_col], inplace=True)
        
        # Handle categorical variables
        categorical_cols = df.select_dtypes(include=['object']).columns
        if len(categorical_cols) > 0:
            df = pd.get_dummies(df, columns=categorical_cols)
        
        # Extract features and labels
        X = df.drop(columns=["label"]).values
        y = df["label"].values
        feature_names = df.drop(columns=["label"]).columns.tolist()
        
        return X, y, feature_names
    
    def _engineer_nsl_kdd_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer additional features for NSL-KDD dataset."""
        # Create interaction features
        df['bytes_ratio'] = df['src_bytes'] / (df['dst_bytes'] + 1)
        df['packet_ratio'] = df['count'] / (df['srv_count'] + 1)
        
        # Create rate-based features
        df['error_rate'] = (df['serror_rate'] + df['rerror_rate']) / 2
        df['service_rate'] = df['same_srv_rate'] + df['diff_srv_rate']
        
        # Create security-related features
        df['security_score'] = (
            df['num_failed_logins'] * 2 +
            df['num_compromised'] * 3 +
            df['root_shell'] * 5 +
            df['su_attempted'] * 2
        )
        
        return df
    
    def _engineer_unsw_nb15_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer additional features for UNSW-NB15 dataset."""
        # Create packet-based features
        df['total_packets'] = df['spkts'] + df['dpkts']
        df['total_bytes'] = df['sbytes'] + df['dbytes']
        df['avg_packet_size'] = df['total_bytes'] / (df['total_packets'] + 1)
        
        # Create ratio features
        df['packet_ratio'] = df['spkts'] / (df['dpkts'] + 1)
        df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1)
        
        # Create time-based features
        df['packets_per_second'] = df['total_packets'] / (df['dur'] + 1)
        df['bytes_per_second'] = df['total_bytes'] / (df['dur'] + 1)
        
        return df
    
    def _apply_advanced_preprocessing(self, X: np.ndarray, y: np.ndarray, 
                                    feature_names: List[str]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Apply advanced preprocessing techniques."""
        print("🔧 Applying advanced preprocessing...")
        
        # Handle missing values
        X = self._handle_missing_values(X)
        
        # Feature scaling
        X = self._scale_features(X)
        
        # Advanced balancing
        if self.advanced_balancing:
            X, y = self._apply_advanced_balancing(X, y)
        
        # Feature selection (optional)
        X, feature_names = self._select_features(X, y, feature_names)
        
        return X, y, feature_names
    
    def _handle_missing_values(self, X: np.ndarray) -> np.ndarray:
        """Handle missing values in the dataset."""
        # Replace NaN with 0 for numerical features
        X = np.nan_to_num(X, nan=0.0)
        return X
    
    def _scale_features(self, X: np.ndarray) -> np.ndarray:
        """Scale features using robust scaling."""
        # Use robust scaling to handle outliers
        from sklearn.preprocessing import RobustScaler
        scaler = RobustScaler()
        return scaler.fit_transform(X)
    
    def _apply_advanced_balancing(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Apply advanced data balancing techniques."""
        from collections import Counter
        class_counts = Counter(y)
        
        if len(class_counts) > 2:
            # Multi-class balancing
            min_samples = min(class_counts.values())
            if min_samples < 100:
                # Use ADASYN for severe imbalance
                adasyn = ADASYN(random_state=42)
                X, y = adasyn.fit_resample(X, y)
                print(f"✅ Applied ADASYN balancing")
            else:
                # Use SMOTE for moderate imbalance
                smote = SMOTE(random_state=42, k_neighbors=min(5, min_samples - 1))
                X, y = smote.fit_resample(X, y)
                print(f"✅ Applied SMOTE balancing")
        else:
            # Binary classification
            if class_counts[0] / class_counts[1] > 2 or class_counts[1] / class_counts[0] > 2:
                smote = SMOTE(random_state=42)
                X, y = smote.fit_resample(X, y)
                print(f"✅ Applied SMOTE balancing for binary classification")
        
        return X, y
    
    def _select_features(self, X: np.ndarray, y: np.ndarray, 
                        feature_names: List[str]) -> Tuple[np.ndarray, List[str]]:
        """Select the most important features."""
        try:
            from sklearn.feature_selection import SelectKBest, f_classif
            
            # Select top 80% of features
            k = int(X.shape[1] * 0.8)
            selector = SelectKBest(score_func=f_classif, k=k)
            X_selected = selector.fit_transform(X, y)
            
            # Get selected feature names
            selected_indices = selector.get_support()
            selected_feature_names = [feature_names[i] for i in range(len(feature_names)) if selected_indices[i]]
            
            print(f"✅ Selected {X_selected.shape[1]} most important features")
            return X_selected, selected_feature_names
            
        except Exception as e:
            print(f"⚠️ Feature selection failed: {e}")
            return X, feature_names
    
    def _validate_nsl_kdd(self, df: pd.DataFrame):
        """Validate NSL-KDD dataset."""
        for _, row in df.head(10).iterrows():
            try:
                NSLKDDRow(**row.to_dict())
            except ValidationError as e:
                raise ValueError(f"NSL-KDD data validation error: {e}")
    
    def _validate_unsw_nb15(self, df: pd.DataFrame):
        """Validate UNSW-NB15 dataset."""
        for _, row in df.head(10).iterrows():
            try:
                UNSWNB15Row(**row.to_dict())
            except ValidationError as e:
                raise ValueError(f"UNSW-NB15 data validation error: {e}")


# --- Legacy functions for backward compatibility ---
def validate_nsl_kdd(df):
    """Legacy validation function."""
    loader = AdvancedDatasetLoader()
    loader._validate_nsl_kdd(df)

def validate_unsw_nb15(df):
    """Legacy validation function."""
    loader = AdvancedDatasetLoader()
    loader._validate_unsw_nb15(df)

def load_nsl_kdd(train_path, test_path, binary_classification=True):
    """Legacy NSL-KDD loader."""
    loader = AdvancedDatasetLoader()
    X, y, _ = loader.load_dataset('nsl_kdd', train_path, test_path, binary_classification)
    return X, y

def load_unsw_nb15(train_path, test_path, binary_classification=True):
    """Legacy UNSW-NB15 loader."""
    loader = AdvancedDatasetLoader()
    X, y, _ = loader.load_dataset('unsw_nb15', train_path, test_path, binary_classification)
    return X, y

def load_multiple_datasets(dataset_configs, binary_classification=True, balance_data=True):
    """Legacy multi-dataset loader."""
    loader = AdvancedDatasetLoader()
    loader.advanced_balancing = balance_data
    
    X_list = []
    y_list = []
    feature_names_list = []
    
    for ds in dataset_configs:
        X, y, feature_names = loader.load_dataset(
            ds['type'], ds['train'], ds['test'], binary_classification
        )
        X_list.append(X)
        y_list.append(y)
        feature_names_list.append(feature_names)
    
    # Combine datasets
    max_features = max(X.shape[1] for X in X_list)
    for i in range(len(X_list)):
        if X_list[i].shape[1] < max_features:
            pad_width = max_features - X_list[i].shape[1]
            X_list[i] = np.pad(X_list[i], ((0, 0), (0, pad_width)), mode='constant')
    
    X = np.vstack(X_list)
    y = np.hstack(y_list)
    
    return X, y

def load_combined_datasets(binary_classification=True, balance_data=True):
    """Legacy combined dataset loader."""
    return load_multiple_datasets([
        {'type': 'nsl_kdd', 'train': 'data/KDDTrain+.txt', 'test': 'data/KDDTest+.txt'},
        {'type': 'unsw_nb15', 'train': 'data/UNSW_NB15_training-set.csv', 'test': 'data/UNSW_NB15_testing-set.csv'}
    ], binary_classification, balance_data)