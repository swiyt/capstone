
import numpy as np 
import pandas as pd 
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer 
from sklearn.linear_model import LogisticRegression

def sanitization(web):
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash)) 
    return token

#Program
urls = []
urls.append(input("Enter the URL here: "))

whitelist = ['gmail.com', 'github.com', 'google.com', 'youtube.com', 'hackthebox.com']
s_url = []
for i in urls:
    if i not in whitelist:
        s_url.append(i)

file = "Extract/pickel_model.pkl"
with open(file, 'rb') as f:
    lgr = pickle.load(f)
f.close()

file = "Extract/pickle_vector.pkl"
with open(file, 'rb') as f2:
    vectorizer = pickle.load(f2)
f2.close()

for site in whitelist:
    s_url.append(site)

x = vectorizer.transform(s_url)
y_predict = lgr.predict(x)

predict = list(y_predict)
for j in range(0,len(whitelist)):
    predict.append('good')
print("\nThe entered domain is: ", predict[0])


