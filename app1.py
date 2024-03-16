import streamlit as st
import pandas as pd
import numpy as np
import pickle
import random
import pickle
from urllib.parse import urlparse
import whois
import requests
from bs4 import BeautifulSoup
import datetime
from dateutil.parser import parse as date_parse
import re
from streamlit_login_auth_ui.widgets import __login__

st.set_page_config(page_title = "Phishing Detection")
__login__obj = __login__(auth_token = "courier_auth_token", 
                    company_name = "Shims",
                    width = 200, height = 250, 
                    logout_button_name = 'Logout', hide_menu_bool = False, 
                    hide_footer_bool = False, 
                    lottie_url = 'https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json')

LOGGED_IN = __login__obj.build_login_ui()

if LOGGED_IN == True:

    st.markdown("Your Streamlit Application Begins here!")
    st.header("Phishing Detection")

    url = st.text_input("Enter the URL to check")

    predict_button = st.button("Click to Predict the status of url")

    data = pd.read_csv('features_dataset.csv')

    def extract_url_features(url):
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Feature: Length of URL
        length_url = len(url)

        # Feature: Random Domain
        random_domain = True if 'random' in parsed_url.netloc else False

        # Feature: Number of External Redirections
        try:
            response = requests.head(url, allow_redirects=True)
            nb_external_redirection = len(response.history)
            if nb_external_redirection <= 1:
                nb_external_redirection = 1
            elif 1 < nb_external_redirection <= 4:
                nb_external_redirection = 0
            else:
                nb_external_redirection = -1
        except:
            nb_external_redirection = -1

        # Feature: Suspicious TLD
        suspicious_tld = 1 if parsed_url.netloc.endswith('.xyz') else -1

        # Feature: External Favicon
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            external_favicon = -1
            for link in soup.find_all('link', rel='icon', href=True):
                if url not in link['href'] and domain not in link['href']:
                    external_favicon = 1
                    break
        except:
            external_favicon = -1

        # Feature: Links in Tags
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            i, success = 0, 0
            for tag in ['a', 'img', 'audio', 'embed', 'iframe']:
                for item in soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer('\.', item['src'])]
                    if url in item['src'] or domain in item['src'] or len(dots) == 1:
                        success += 1
                    i += 1
            links_in_tags = success / float(i) * 100 if i > 0 else 0
        except:
            links_in_tags = 0

        # Feature: SFH
        try:
            sfh = check_sfh(url)
        except:
            sfh = -1

        # Feature: Domain in Title
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.lower() if soup.title else None
            domain_in_title = 1 if title and domain in title else -1
        except:
            domain_in_title = -1

        # Feature: Domain Age
        try:
            whois_info = whois.whois(domain)
            creation_date = whois_info.creation_date
            expiration_date = whois_info.expiration_date
            today = datetime.datetime.now().date()
            if isinstance(creation_date, list):
                creation_date = min(creation_date)
            creation_date = date_parse(str(creation_date))
            if isinstance(expiration_date, list):
                expiration_date = max(expiration_date)
            expiration_date = date_parse(str(expiration_date))
            if (expiration_date is None or creation_date is None):
                domain_age = -1
            elif ((expiration_date - today).days < 30):
                domain_age = -1
            else:
                domain_age = (today - creation_date.date()).days
        except:
            domain_age = -1

        # Feature: Web Traffic
        try:
            web_traffic = get_web_traffic(url)
        except:
            web_traffic = -1

        # Return the extracted features as a dictionary
        features = {
            'length_url': length_url,
            'random_domain': random_domain,
            'nb_external_redirection': nb_external_redirection,
            'suspecious_tld': suspicious_tld,
            'external_favicon': external_favicon,
            'links_in_tags': links_in_tags,
            'sfh': sfh,
            'domain_in_title': domain_in_title,
            'domain_age': domain_age,
            'web_traffic': web_traffic
        }

        return features

    # Example function to check SFH
    def check_sfh(url):
        try:
            # Implement your logic to check for SFH
            return True
        except:
            return False

    # Example function to get web traffic (for demonstration purposes)
    def get_web_traffic(url):
        traffic_levels = ['0', '1', '2']
        return random.choice(traffic_levels)

    if predict_button:
        try:
            url_features = extract_url_features(url)
            st.write(url_features)

            # Load the trained model from the pickle file
            with open('models/rf_model_n.pkl', 'rb') as model_file:
                model = pickle.load(model_file)

            def predict_url(url):
                # Extract features from the URL
                url_features = extract_url_features(url)

                # Convert the features to a format expected by the model (if necessary)
                # Make sure the order of features matches the input expected by the model
                model_input = [url_features['length_url'],
                                int(url_features['random_domain']),
                                url_features['nb_external_redirection'],
                                int(url_features['suspecious_tld']),
                                int(url_features['external_favicon']),
                                url_features['links_in_tags'],
                                int(url_features['sfh']),
                                int(url_features['domain_in_title']),
                                url_features['domain_age'],
                                url_features['web_traffic']]

                # Make predictions using the model
                prediction = model.predict([model_input])
                return prediction[0]

            result = predict_url(url)
            st.write(result)

            # Assuming the model predicts 1 for phishing and 0 for legitimate
            if result == "phishing":
                st.write("The model predicts: phishing")
            else:
                st.write("The model predicts: legitimate")
        except Exception as e:
            st.write(f"Error: {e}")