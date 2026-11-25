import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

df = pd.read_csv("friday.csv")
df.columns = df.columns.str.strip()

# Binary target: attack vs benign
y = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int)

# Numeric features only; drop the damaged Timestamp and the label
X = df.drop(columns=["Label", "Src IP dec", "Dst IP dec", "Src Port"], errors="ignore").select_dtypes(include=[np.number])
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
model.fit(X_train, y_train)
pred = model.predict(X_test)

print(classification_report(y_test, pred, target_names=["BENIGN", "ATTACK"]))
print(confusion_matrix(y_test, pred))

imp = pd.Series(model.feature_importances_, index=X.columns)
print(imp.sort_values(ascending=False).head(10))

lab = df["Label"].str.strip().str.lower()
rng = np.random.RandomState(42)
benign = lab == "benign"
train_benign = benign & (rng.rand(len(df)) < 0.7)
test_benign = benign & ~train_benign

train = train_benign | (lab == "portscan")
test = test_benign | (lab == "ddos")

m = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
m.fit(X[train], y[train])
print(classification_report(y[test], m.predict(X[test]), target_names=["BENIGN", "ATTACK"]))