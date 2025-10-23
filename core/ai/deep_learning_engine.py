"""
CyberGuardian AI - Deep Learning Engine
Advanced Neural Network Security System

Provides deep learning capabilities:
- CNN for image-based malware classification
- RNN/LSTM for sequential attack detection
- Transformer models for code analysis
- Ensemble learning for maximum accuracy
- Transfer learning support

Security Knowledge Applied:
- Deep learning for malware detection
- Sequential pattern recognition
- Code embedding techniques
- Adversarial robustness
- Model interpretability
"""

import logging
import os
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json
import pickle

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import deep learning libraries (optional dependencies)
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("TensorFlow not available - deep learning features limited")

try:
    from sklearn.ensemble import VotingClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - some features limited")


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    loss: float
    training_time: float
    inference_time: float


@dataclass
class TrainingConfig:
    """Training configuration"""
    epochs: int = 50
    batch_size: int = 32
    learning_rate: float = 0.001
    validation_split: float = 0.2
    early_stopping_patience: int = 10
    model_checkpoint: bool = True


class DeepLearningEngine:
    """
    Deep learning engine for advanced threat detection.
    Supports CNN, RNN, LSTM, and Transformer architectures.
    """
    
    def __init__(self, model_dir: str = None):
        """
        Initialize deep learning engine.
        
        Args:
            model_dir: Directory for model storage
        """
        # Setup model directory
        if model_dir:
            self.model_dir = Path(model_dir)
        else:
            home = Path.home()
            self.model_dir = home / '.cyberguardian' / 'models' / 'deep_learning'
        
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Models
        self.models: Dict[str, Any] = {}
        self.model_metadata: Dict[str, Dict] = {}
        
        # Statistics
        self.stats = {
            'total_models': 0,
            'trained_models': 0,
            'total_predictions': 0,
            'accuracy_avg': 0.0
        }
        
        # Check TensorFlow availability
        if not TF_AVAILABLE:
            logger.warning("⚠️ TensorFlow not installed - install with: pip install tensorflow")
        else:
            logger.info(f"✅ TensorFlow {tf.__version__} available")
            # Set memory growth to avoid GPU memory issues
            self._configure_tensorflow()
        
        logger.info(f"DeepLearningEngine initialized at {self.model_dir}")
    
    def _configure_tensorflow(self):
        """Configure TensorFlow settings"""
        try:
            # Enable memory growth for GPU
            gpus = tf.config.list_physical_devices('GPU')
            if gpus:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"✅ GPU available: {len(gpus)} device(s)")
            else:
                logger.info("Running on CPU")
        except Exception as e:
            logger.warning(f"GPU configuration failed: {e}")
    
    # ==================== CNN MODELS ====================
    
    def build_cnn_classifier(self, input_shape: Tuple[int, ...],
                            num_classes: int, name: str = "cnn_classifier") -> Any:
        """
        Build CNN model for image-based malware classification.
        
        Args:
            input_shape: Input shape (height, width, channels)
            num_classes: Number of output classes
            name: Model name
            
        Returns:
            Compiled CNN model
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for CNN models")
        
        model = models.Sequential(name=name)
        
        # Convolutional layers
        model.add(layers.Conv2D(32, (3, 3), activation='relu', input_shape=input_shape))
        model.add(layers.MaxPooling2D((2, 2)))
        model.add(layers.BatchNormalization())
        
        model.add(layers.Conv2D(64, (3, 3), activation='relu'))
        model.add(layers.MaxPooling2D((2, 2)))
        model.add(layers.BatchNormalization())
        
        model.add(layers.Conv2D(128, (3, 3), activation='relu'))
        model.add(layers.MaxPooling2D((2, 2)))
        model.add(layers.BatchNormalization())
        
        # Dense layers
        model.add(layers.Flatten())
        model.add(layers.Dense(256, activation='relu'))
        model.add(layers.Dropout(0.5))
        model.add(layers.Dense(128, activation='relu'))
        model.add(layers.Dropout(0.3))
        
        # Output layer
        if num_classes == 2:
            model.add(layers.Dense(1, activation='sigmoid'))
            loss = 'binary_crossentropy'
        else:
            model.add(layers.Dense(num_classes, activation='softmax'))
            loss = 'categorical_crossentropy'
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=loss,
            metrics=['accuracy', 'precision', 'recall']
        )
        
        self.models[name] = model
        logger.info(f"✅ CNN model built: {name}")
        logger.info(f"   Parameters: {model.count_params():,}")
        
        return model
    
    # ==================== RNN/LSTM MODELS ====================
    
    def build_lstm_classifier(self, sequence_length: int, num_features: int,
                             num_classes: int, name: str = "lstm_classifier") -> Any:
        """
        Build LSTM model for sequential attack detection.
        
        Args:
            sequence_length: Length of input sequences
            num_features: Number of features per timestep
            num_classes: Number of output classes
            name: Model name
            
        Returns:
            Compiled LSTM model
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for LSTM models")
        
        model = models.Sequential(name=name)
        
        # LSTM layers
        model.add(layers.LSTM(128, return_sequences=True, 
                            input_shape=(sequence_length, num_features)))
        model.add(layers.Dropout(0.3))
        
        model.add(layers.LSTM(64, return_sequences=True))
        model.add(layers.Dropout(0.3))
        
        model.add(layers.LSTM(32))
        model.add(layers.Dropout(0.2))
        
        # Dense layers
        model.add(layers.Dense(64, activation='relu'))
        model.add(layers.Dropout(0.2))
        
        # Output layer
        if num_classes == 2:
            model.add(layers.Dense(1, activation='sigmoid'))
            loss = 'binary_crossentropy'
        else:
            model.add(layers.Dense(num_classes, activation='softmax'))
            loss = 'categorical_crossentropy'
        
        # Compile
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=loss,
            metrics=['accuracy']
        )
        
        self.models[name] = model
        logger.info(f"✅ LSTM model built: {name}")
        logger.info(f"   Parameters: {model.count_params():,}")
        
        return model
    
    # ==================== TRANSFORMER MODELS ====================
    
    def build_transformer_classifier(self, sequence_length: int, num_features: int,
                                    num_classes: int, name: str = "transformer_classifier") -> Any:
        """
        Build Transformer model for code analysis.
        
        Args:
            sequence_length: Input sequence length
            num_features: Feature dimension
            num_classes: Number of output classes
            name: Model name
            
        Returns:
            Compiled Transformer model
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for Transformer models")
        
        # Input
        inputs = layers.Input(shape=(sequence_length, num_features))
        
        # Positional encoding (simple version)
        x = inputs
        
        # Multi-head attention
        attention_output = layers.MultiHeadAttention(
            num_heads=4, 
            key_dim=num_features
        )(x, x)
        
        # Add & Norm
        x = layers.Add()([x, attention_output])
        x = layers.LayerNormalization(epsilon=1e-6)(x)
        
        # Feed-forward network
        ff_output = layers.Dense(128, activation='relu')(x)
        ff_output = layers.Dropout(0.1)(ff_output)
        ff_output = layers.Dense(num_features)(ff_output)
        
        # Add & Norm
        x = layers.Add()([x, ff_output])
        x = layers.LayerNormalization(epsilon=1e-6)(x)
        
        # Global average pooling
        x = layers.GlobalAveragePooling1D()(x)
        
        # Dense layers
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        
        # Output
        if num_classes == 2:
            outputs = layers.Dense(1, activation='sigmoid')(x)
            loss = 'binary_crossentropy'
        else:
            outputs = layers.Dense(num_classes, activation='softmax')(x)
            loss = 'categorical_crossentropy'
        
        # Create model
        model = models.Model(inputs=inputs, outputs=outputs, name=name)
        
        # Compile
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.0001),
            loss=loss,
            metrics=['accuracy']
        )
        
        self.models[name] = model
        logger.info(f"✅ Transformer model built: {name}")
        logger.info(f"   Parameters: {model.count_params():,}")
        
        return model
    
    # ==================== TRAINING ====================
    
    def train_model(self, model_name: str, X_train: np.ndarray, y_train: np.ndarray,
                   X_val: np.ndarray = None, y_val: np.ndarray = None,
                   config: TrainingConfig = None) -> ModelMetrics:
        """
        Train a deep learning model.
        
        Args:
            model_name: Name of model to train
            X_train: Training data
            y_train: Training labels
            X_val: Validation data (optional)
            y_val: Validation labels (optional)
            config: Training configuration
            
        Returns:
            ModelMetrics with training results
        """
        if model_name not in self.models:
            raise ValueError(f"Model not found: {model_name}")
        
        model = self.models[model_name]
        
        if config is None:
            config = TrainingConfig()
        
        logger.info(f"🎓 Training model: {model_name}")
        logger.info(f"   Training samples: {len(X_train)}")
        logger.info(f"   Epochs: {config.epochs}, Batch size: {config.batch_size}")
        
        # Callbacks
        callbacks = []
        
        # Early stopping
        callbacks.append(keras.callbacks.EarlyStopping(
            monitor='val_loss' if X_val is not None else 'loss',
            patience=config.early_stopping_patience,
            restore_best_weights=True
        ))
        
        # Model checkpoint
        if config.model_checkpoint:
            checkpoint_path = self.model_dir / f"{model_name}_checkpoint.h5"
            callbacks.append(keras.callbacks.ModelCheckpoint(
                filepath=str(checkpoint_path),
                monitor='val_loss' if X_val is not None else 'loss',
                save_best_only=True
            ))
        
        # Training
        start_time = datetime.now()
        
        if X_val is not None:
            validation_data = (X_val, y_val)
        else:
            validation_data = None
        
        history = model.fit(
            X_train, y_train,
            epochs=config.epochs,
            batch_size=config.batch_size,
            validation_data=validation_data,
            validation_split=config.validation_split if validation_data is None else 0.0,
            callbacks=callbacks,
            verbose=1
        )
        
        training_time = (datetime.now() - start_time).total_seconds()
        
        # Evaluate
        if X_val is not None:
            loss, accuracy, precision, recall = model.evaluate(X_val, y_val, verbose=0)
        else:
            loss = history.history['loss'][-1]
            accuracy = history.history['accuracy'][-1]
            precision = history.history.get('precision', [0])[-1]
            recall = history.history.get('recall', [0])[-1]
        
        # Calculate F1
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Measure inference time
        sample = X_train[:1]
        start = datetime.now()
        _ = model.predict(sample, verbose=0)
        inference_time = (datetime.now() - start).total_seconds()
        
        # Create metrics
        metrics = ModelMetrics(
            accuracy=float(accuracy),
            precision=float(precision),
            recall=float(recall),
            f1_score=float(f1_score),
            loss=float(loss),
            training_time=training_time,
            inference_time=inference_time
        )
        
        # Save metadata
        self.model_metadata[model_name] = {
            'trained': True,
            'training_date': datetime.now().isoformat(),
            'metrics': {
                'accuracy': metrics.accuracy,
                'precision': metrics.precision,
                'recall': metrics.recall,
                'f1_score': metrics.f1_score
            },
            'config': {
                'epochs': config.epochs,
                'batch_size': config.batch_size
            }
        }
        
        # Update stats
        self.stats['trained_models'] += 1
        self.stats['accuracy_avg'] = np.mean([
            m['metrics']['accuracy'] 
            for m in self.model_metadata.values()
        ])
        
        logger.info(f"✅ Training complete!")
        logger.info(f"   Accuracy: {metrics.accuracy:.4f}")
        logger.info(f"   Precision: {metrics.precision:.4f}")
        logger.info(f"   Recall: {metrics.recall:.4f}")
        logger.info(f"   F1 Score: {metrics.f1_score:.4f}")
        logger.info(f"   Training time: {training_time:.2f}s")
        
        return metrics
    
    # ==================== INFERENCE ====================
    
    def predict(self, model_name: str, X: np.ndarray) -> np.ndarray:
        """
        Make predictions using a trained model.
        
        Args:
            model_name: Name of model
            X: Input data
            
        Returns:
            Predictions
        """
        if model_name not in self.models:
            raise ValueError(f"Model not found: {model_name}")
        
        model = self.models[model_name]
        
        predictions = model.predict(X, verbose=0)
        
        self.stats['total_predictions'] += len(X)
        
        return predictions
    
    def predict_binary(self, model_name: str, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """
        Binary classification prediction.
        
        Args:
            model_name: Model name
            X: Input data
            threshold: Classification threshold
            
        Returns:
            Binary predictions (0 or 1)
        """
        predictions = self.predict(model_name, X)
        return (predictions > threshold).astype(int)
    
    # ==================== MODEL MANAGEMENT ====================
    
    def save_model(self, model_name: str, save_path: str = None) -> bool:
        """
        Save a trained model to disk.
        
        Args:
            model_name: Name of model to save
            save_path: Custom save path (optional)
            
        Returns:
            True if saved successfully
        """
        if model_name not in self.models:
            return False
        
        try:
            model = self.models[model_name]
            
            if save_path is None:
                save_path = self.model_dir / f"{model_name}.h5"
            
            model.save(save_path)
            
            # Save metadata
            metadata_path = Path(str(save_path).replace('.h5', '_metadata.json'))
            with open(metadata_path, 'w') as f:
                json.dump(self.model_metadata.get(model_name, {}), f, indent=2)
            
            logger.info(f"💾 Model saved: {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, model_name: str, model_path: str) -> bool:
        """
        Load a trained model from disk.
        
        Args:
            model_name: Name to assign to loaded model
            model_path: Path to model file
            
        Returns:
            True if loaded successfully
        """
        try:
            if not TF_AVAILABLE:
                raise ImportError("TensorFlow required to load models")
            
            model = keras.models.load_model(model_path)
            self.models[model_name] = model
            
            # Load metadata if exists
            metadata_path = Path(str(model_path).replace('.h5', '_metadata.json'))
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    self.model_metadata[model_name] = json.load(f)
            
            logger.info(f"📂 Model loaded: {model_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        self.stats['total_models'] = len(self.models)
        return self.stats.copy()


def create_deep_learning_engine(model_dir: str = None) -> DeepLearningEngine:
    """Factory function to create DeepLearningEngine instance"""
    return DeepLearningEngine(model_dir=model_dir)


# Testing
if __name__ == "__main__":
    print("🧠 CyberGuardian - Deep Learning Engine Test\n")
    
    engine = create_deep_learning_engine()
    
    print(f"📂 Model directory: {engine.model_dir}")
    print(f"🔧 TensorFlow available: {TF_AVAILABLE}")
    
    if TF_AVAILABLE:
        print("\n🧠 Test 1: Build CNN classifier")
        try:
            model = engine.build_cnn_classifier(
                input_shape=(28, 28, 1),
                num_classes=2,
                name="test_cnn"
            )
            print(f"   ✅ CNN model created")
            print(f"   Parameters: {model.count_params():,}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print("\n🧠 Test 2: Build LSTM classifier")
        try:
            model = engine.build_lstm_classifier(
                sequence_length=100,
                num_features=10,
                num_classes=2,
                name="test_lstm"
            )
            print(f"   ✅ LSTM model created")
            print(f"   Parameters: {model.count_params():,}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print("\n🧠 Test 3: Build Transformer classifier")
        try:
            model = engine.build_transformer_classifier(
                sequence_length=50,
                num_features=64,
                num_classes=2,
                name="test_transformer"
            )
            print(f"   ✅ Transformer model created")
            print(f"   Parameters: {model.count_params():,}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    else:
        print("\n⚠️  TensorFlow not available")
        print("   Install with: pip install tensorflow")
    
    print("\n📊 Statistics:")
    stats = engine.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Deep Learning Engine test complete!")