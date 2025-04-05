import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

class IntrusionDetectionModel:
    def __init__(self, timesteps, features):
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
        
        return model
        
    def train(self, X_train, y_train, epochs=10, batch_size=32, validation_split=0.2):
        return self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split
        )
        
    def predict(self, X):
        return self.model.predict(X)