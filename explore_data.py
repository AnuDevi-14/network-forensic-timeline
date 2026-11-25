import pandas as pd

# Load the dataset
df = pd.read_csv(r"D:\network-forensics\friday.csv")

# Basic checks
print("Shape:", df.shape)
print("\nColumns:\n", df.columns.tolist())
print("\nFirst 5 rows:\n", df.head())

# Check the label column (attack types)
if 'Label' in df.columns:
    print("\nLabel value counts:\n", df['Label'].value_counts())
else:
    print("\nNo 'Label' column found — check exact column name (might have leading space, e.g. ' Label')")