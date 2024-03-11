from flask import Flask, render_template, request
import pickle
import pandas as pd
import feature
data  = pd.read_csv('features_dataset.csv')

app = Flask(__name__)

# Load the trained model
model=pickle.load(open('models/rf_model.pkl','rb'))

# Define the feature names used during training
feature_names = ['length_url','random_domain',
                'nb_external_redirection','suspecious_tld',
                'external_favicon','links_in_tags','sfh','domain_in_title',
                'domain_age','web_traffic']  # List all feature names used during training

def extract_features(url):
    # Implement your feature extraction logic here
    # Use the same logic you used for training to extract features for the provided URL
    # Return the features as a dictionary

    # Example (replace this with your actual feature extraction):
    features = {'length_url','random_domain',
                'nb_external_redirection','suspecious_tld',
                'external_favicon','links_in_tags','sfh','domain_in_title',
                'domain_age','web_traffic'}
    
    return features

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        # Extract features for the provided URL (modify this part based on your features extraction logic)
        features = extract_features(url)
        print(features)
        
        # Create a DataFrame with the extracted features
        # Make prediction
        x = data.iloc[:,:-1]
        print(x)
        prediction = model.predict(x)[0]
        print(prediction)
        # Convert the prediction to a human-readable format
        result = 'Phishing' if prediction == 1 else 'Legitimate'
        
        return render_template('result.html', url=url, result=result)

if __name__ == '__main__':
    app.run(debug=True)
