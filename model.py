import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
import logging

class IntrusionDetectionModel:
    def __init__(self, timesteps, features):
        # Store these for potential validation when loading a model
        self.expected_timesteps = timesteps
        self.expected_features = features
        # Build a new model by default
        self.model = self._build_model(timesteps, features)
        
    def _build_model(self, timesteps, features):
        model = Sequential([
            LSTM(64, input_shape=(timesteps, features), return_sequences=True),
            LSTM(32),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        logging.info(f"Built new model with input shape ({timesteps}, {features})")
        return model
        
    def train(self, X_train, y_train, epochs=10, batch_size=32, validation_data=None, callbacks=None):
        logging.info(f"Starting training with X_train shape: {X_train.shape}")
        return self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=validation_data,
            callbacks=callbacks
        )
        
    def predict(self, X):
        # X should be of shape (num_samples, timesteps, features)
        if X.ndim == 2: # If we get a 2D array (timesteps, features) for a single prediction instance
            # Reshape to (1, timesteps, features) as expected by LSTM layer
            X = np.reshape(X, (1, X.shape[0], X.shape[1]))
        elif X.ndim != 3:
            raise ValueError(f"Input X for prediction must be 3-dimensional (samples, timesteps, features) or 2-dimensional (timesteps, features for a single sample), got {X.ndim} dimensions.")
        return self.model.predict(X)

    def load_existing_model(self, filepath):
        logging.info(f"Loading existing model from {filepath}...")
        try:
            loaded_model = load_model(filepath)
            # Basic validation: check input layer shape if possible
            if hasattr(loaded_model, 'input_shape') and loaded_model.input_shape[1:] != (self.expected_timesteps, self.expected_features):
                logging.warning(f"Loaded model input shape {loaded_model.input_shape[1:]} does not match configured timesteps/features ({self.expected_timesteps}, {self.expected_features}). Ensure consistency.")
            self.model = loaded_model
            logging.info("Model loaded successfully.")
        except Exception as e:
            logging.error(f"Failed to load model from {filepath}: {e}. Using the default built model.")
