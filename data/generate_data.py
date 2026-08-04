import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score 
from sklearn.metrics import classification_report
from joblib import dump, load


#MALICIOUS
durations_malicious = np.random.uniform(0.01, 1.0, size = 1001)

connection_counts_malicious = np.random.randint(4,11, size = 1001)

df1 = {
    "duration": durations_malicious,
    "connection_count": connection_counts_malicious, 
    "label": 1 
    }

malicious_df = pd.DataFrame(df1)

#BENIGN
durations_benign = np.random.uniform(0.5, 11, size = 1001)

connection_counts_benign = np.random.randint(1,6, size = 1001)

df2 = {
    "duration": durations_benign,
    "connection_count": connection_counts_benign,
    "label": 0
}

benign_df = pd.DataFrame(df2)

df3 = pd.concat([benign_df,malicious_df], ignore_index=1)

x = (df3[['duration', 'connection_count']])

y = (df3['label'])

X_train, X_test, y_train, y_test = train_test_split(
    x, y, test_size=0.2
)

print(X_train)
print(X_test)
print(y_train)
print(y_test)

clf = RandomForestClassifier()
clf.fit(X_train,y_train)
dump(clf, 'models/RFC.joblib')


y_prediction = clf.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_prediction):.2f}")
print(classification_report(y_test,y_prediction))