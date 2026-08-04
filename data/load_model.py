from joblib import load
loaded_clf = load('D:/Projects/Network-Traffic-Classifier/models/RFC.joblib')
print(loaded_clf.predict([[0.2,8]]))