import pandas as pd
df = pd.read_csv(r"D:\network-forensics\friday.csv")
print(df['Timestamp'].head(10).tolist())